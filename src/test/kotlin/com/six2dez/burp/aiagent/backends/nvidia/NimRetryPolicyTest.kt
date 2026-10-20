package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NimRetryPolicyTest {
    @Test
    fun `429 without Retry After waits for capacity instead of retrying in one second`() {
        assertTrue(NimRetryPolicy.delayMs(TransportResponse(429, "", false), 0) in 30_000..30_249)
        assertTrue(NimRetryPolicy.delayMs(TransportResponse(429, "", false), 1) in 60_000..60_249)
    }

    @Test
    fun `server failures use slower bounded backoff and supplied Retry After wins`() {
        assertTrue(NimRetryPolicy.delayMs(TransportResponse(500, "", false), 0) in 5000..5249)
        assertTrue(NimRetryPolicy.delayMs(TransportResponse(500, "", false), 1) in 10_000..10_249)
        assertEquals(0, NimRetryPolicy.delayMs(TransportResponse(503, "", false, mapOf("retry-after" to "0")), 0))
    }
}
