package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class NimHttpCallTest {
    @Test
    fun hardDeadlineReturnsEvenWhenNativeTransportIgnoresInterruptsAndRetainsItsSlot() {
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doAnswer {
            entered.countDown()
            while (release.count > 0) {
                try {
                    release.await(1, TimeUnit.SECONDS)
                } catch (_: InterruptedException) {
                    // Emulate a native call which cannot be cancelled by Future.cancel(true).
                }
            }
            TransportResponse(200, "{}", true)
        }.whenever(transport).post(any(), any(), any(), any())
        val gate = NimRequestCoordinator()
        val options = NvidiaNimOptions(maxConcurrency = 1)
        try {
            assertThrows(SocketTimeoutException::class.java) {
                NimHttpCall(gate).post(transport, "https://example.test", emptyMap(), "{}", options, deadline(500)) { false }
            }
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertThrows(SocketTimeoutException::class.java) { gate.acquire(options, deadline(100)) { false } }
            release.countDown()
            gate.acquire(options, deadline(2000)) { false }.close()
        } finally {
            release.countDown()
        }
    }

    private fun deadline(ms: Long) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms)
}
