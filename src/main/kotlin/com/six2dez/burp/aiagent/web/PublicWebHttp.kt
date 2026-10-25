package com.six2dez.burp.aiagent.web

import com.six2dez.burp.aiagent.util.scheduleGuarded
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.IOException
import java.net.Proxy
import java.time.Instant
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

/** Dedicated anonymous GET client; it never inherits Burp cookies, API keys or proxy credentials. */
internal class PublicWebHttp(
    private val client: OkHttpClient = defaultClient(),
) : WebTransport {
    private val slots = Semaphore(2)
    private val monitor = ScheduledThreadPoolExecutor(1) { runnable -> Thread(runnable, "burp-ai-web-cancel").apply { isDaemon = true } }.apply { removeOnCancelPolicy = true }

    override fun get(url: String): WebResource {
        check(slots.tryAcquire()) { "Web research is busy; wait for the current requests to finish" }
        try {
            return follow(PublicWebAddress.parse(url).toString())
        } finally {
            slots.release()
        }
    }

    private fun follow(initialUrl: String): WebResource {
        var url = PublicWebAddress.parse(initialUrl)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WebLimits.TIMEOUT_SECONDS)
        repeat(WebLimits.MAX_REDIRECTS + 1) { hop ->
            WebCancellation.check()
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "Web research deadline exceeded" }
            val request =
                Request
                    .Builder()
                    .url(url)
                    .header("User-Agent", WebLimits.USER_AGENT)
                    .header("Accept", "text/html, text/plain, application/json, application/xhtml+xml;q=0.9")
                    .get()
                    .build()
            val call = client.newCall(request)
            call.timeout().timeout(remaining, TimeUnit.NANOSECONDS)
            val worker = Thread.currentThread()
            val cancelled = WebCancellation.current()
            val watch =
                monitor.scheduleGuarded("PublicWebHttp", "cancel", {
                    org.slf4j.LoggerFactory
                        .getLogger(PublicWebHttp::class.java)
                        .warn(it)
                }, 0, CANCEL_POLL_MS, TimeUnit.MILLISECONDS) { if (worker.isInterrupted || cancelled()) call.cancel() }
            try {
                call.execute().use { response ->
                    if (response.code in WebLimits.REDIRECT_STATUSES) {
                        check(hop < WebLimits.MAX_REDIRECTS) { "Web research redirect limit exceeded" }
                        val location = checkNotNull(response.header("Location")) { "Web redirect has no Location" }
                        url = PublicWebAddress.parse(checkNotNull(url.resolve(location)) { "Invalid web redirect" }.toString())
                    } else {
                        return read(response)
                    }
                }
            } finally {
                watch.cancel(false)
            }
        }
        error("Web research redirect limit exceeded")
    }

    private fun read(response: Response): WebResource {
        check(response.isSuccessful && response.code != WebLimits.ACCEPTED_ASYNC_STATUS) { "Web HTTP ${response.code}; provider unavailable or access challenged. No automatic retry." }
        val type = response.body.contentType()
        val media = type?.let { "${it.type}/${it.subtype}" }.orEmpty()
        require(media.startsWith("text/") || media in setOf("application/json", "application/xhtml+xml", "application/xml")) { "Web research supports readable text pages, not downloads" }
        require(response.body.contentLength() <= WebLimits.MAX_BYTES) { "Web page exceeds the 1 MiB reading limit" }
        val source = response.body.source()
        val buffer = okio.Buffer()
        while (buffer.size <= WebLimits.MAX_BYTES) {
            if (Thread.currentThread().isInterrupted) throw IOException("Web research cancelled")
            if (source.read(buffer, minOf(WebLimits.READ_CHUNK_BYTES, WebLimits.MAX_BYTES + 1L - buffer.size)) == -1L) break
        }
        require(buffer.size <= WebLimits.MAX_BYTES) { "Web page exceeds the 1 MiB reading limit" }
        val text = buffer.readByteString().string(type?.charset(Charsets.UTF_8) ?: Charsets.UTF_8)
        return WebResource(response.request.url.toString(), media, text, Instant.now().toString())
    }

    fun close() {
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
        monitor.shutdownNow()
    }

    companion object {
        private const val CANCEL_POLL_MS = 100L

        private fun defaultClient(): OkHttpClient =
            OkHttpClient
                .Builder()
                .dns(PublicWebDns())
                .proxy(Proxy.NO_PROXY)
                .connectTimeout(WebLimits.CONNECT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(WebLimits.TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .callTimeout(WebLimits.TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .retryOnConnectionFailure(false)
                .build()
    }
}
