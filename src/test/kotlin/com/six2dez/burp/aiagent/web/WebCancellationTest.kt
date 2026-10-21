package com.six2dez.burp.aiagent.web

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class WebCancellationTest {
    @Test
    fun cancellationStopsOnlyItsOwnCallAndReleasesTheSlot() {
        val entered = CountDownLatch(1)
        val done = CountDownLatch(1)
        val cancelled = AtomicBoolean(false)
        val failure = AtomicReference<Throwable?>()
        val client =
            OkHttpClient
                .Builder()
                .addInterceptor { chain ->
                    if (chain.request().url.encodedPath == "/slow") {
                        entered.countDown()
                        while (!chain.call().isCanceled()) Thread.sleep(10)
                        throw IOException("Cancelled fixture")
                    }
                    Response
                        .Builder()
                        .request(chain.request())
                        .protocol(Protocol.HTTP_1_1)
                        .code(200)
                        .message("ok")
                        .header("Content-Type", "text/plain")
                        .body("ok".toResponseBody("text/plain".toMediaType()))
                        .build()
                }.build()
        val http = PublicWebHttp(client)
        val worker =
            Thread {
                try {
                    WebCancellation.within(cancelled::get) { http.get("https://example.org/slow") }
                } catch (error: Throwable) {
                    failure.set(error)
                } finally {
                    done.countDown()
                }
            }
        try {
            worker.start()
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertTrue(http.get("https://example.org/fast").body == "ok")
            cancelled.set(true)
            assertTrue(done.await(2, TimeUnit.SECONDS), "Cancellation should close the active HTTP call promptly")
            assertNotNull(failure.get())
            assertTrue(http.get("https://example.org/again").body == "ok")
        } finally {
            cancelled.set(true)
            http.close()
            worker.join(2000)
        }
    }

    @Test
    fun cancelledWorkerDoesNotReadCacheOrStartHttp() {
        var requested = false
        val service =
            WebResearchService(
                WebTransport {
                    requested = true
                    error("must not run")
                },
            )
        org.junit.jupiter.api.Assertions.assertThrows(java.io.InterruptedIOException::class.java) {
            WebCancellation.within({ true }) { service.fetch(WebFetchInput("https://example.org/")) }
        }
        assertFalse(requested)
        assertFalse(WebCancellation.current().invoke())
    }
}
