package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.TransportResponse
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NimErrorInfoTest {
    @Test
    fun `provider prompt echo is classified without copying its text`() {
        val response = TransportResponse(500, """{"error":{"message":"Conversation roles must alternate user and assistant; private secret=nvapi-hidden"}}""", false)
        val result = NimErrorInfo.description(response)
        assertTrue(result.contains("conversation roles"))
        assertFalse(result.contains("nvapi-hidden"))
        assertFalse(result.contains("private"))
    }

    @Test
    fun `context and capacity failures are differentiated`() {
        assertTrue(NimErrorInfo.description(TransportResponse(500, "maximum context length exceeded", false)).contains("context-length"))
        assertTrue(NimErrorInfo.description(TransportResponse(500, "CUDA out of memory", false)).contains("capacity"))
    }

    @Test
    fun `request id permits bounded correlation values but rejects credentials and control characters`() {
        val safe = "123e4567-e89b-12d3-a456-426614174000"
        assertEquals(safe, NimErrorInfo.requestId(TransportResponse(500, "", false, mapOf("nvcf-reqid" to safe))))
        assertEquals(null, NimErrorInfo.requestId(TransportResponse(500, "", false, mapOf("X-Request-ID" to "nvapi-secret"))))
        assertEquals(null, NimErrorInfo.requestId(TransportResponse(500, "", false, mapOf("X-Request-ID" to "request\r\nInjected: header"))))
    }
}
