package com.six2dez.burp.aiagent.web

import okhttp3.Dns
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Native DNS may ignore interrupts; cap the caller wait and the number of orphaned resolvers. */
internal object WebDnsResolver {
    private var pool: ThreadPoolExecutor? = null

    @Synchronized
    private fun executor(): ThreadPoolExecutor =
        pool ?: ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(2)) { runnable ->
            Thread(runnable, "burp-ai-web-dns").apply { isDaemon = true }
        }.also { pool = it }

    fun lookup(
        resolver: Dns,
        hostname: String,
        timeoutMs: Long,
    ): List<InetAddress> {
        val future =
            try {
                executor().submit<List<InetAddress>> { resolver.lookup(hostname) }
            } catch (_: RejectedExecutionException) {
                throw UnknownHostException("Web DNS resolver is busy")
            }
        val failure =
            try {
                return future.get(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                "timed out"
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                "cancelled"
            } catch (_: ExecutionException) {
                "failed"
            } finally {
                future.cancel(true)
            }
        throw UnknownHostException("Web DNS lookup $failure")
    }

    @Synchronized
    fun shutdown() {
        pool?.shutdownNow()
        pool = null
    }
}
