package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class NimProtocolTest {
    @Test
    fun `JSON answers keep Unicode and usage but exclude reasoning`() {
        val result =
            NimProtocol.parse(
                """{"choices":[{"message":{"content":"Привет 🚀","reasoning_content":"private thoughts"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":20}}""",
            )
        assertEquals("Привет 🚀", result.content)
        assertEquals(20, result.usage?.outputTokens)
    }

    @Test
    fun `buffered SSE handles heartbeat reasoning null deltas and trailing usage`() {
        val body =
            """
            : heartbeat

            data: {"choices":[{"delta":{"reasoning_content":"hidden","content":null}}]}

            data: {"choices":[{"delta":{"content":"hello "}}]}

            data: {"choices":[{"delta":{"content":"world"},"finish_reason":"stop"}]}

            data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":34}}

            data: [DONE]
            """.trimIndent().replace("\n", "\r\n")
        val result = NimProtocol.parse(body)
        assertEquals("hello world", result.content)
        assertEquals(34, result.usage?.outputTokens)
    }

    @Test
    fun `unterminated stream fails instead of returning partial findings`() {
        assertThrows(IllegalArgumentException::class.java) {
            NimProtocol.parse("data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
        }
    }

    @Test
    fun `token limit and reasoning only responses have actionable errors`() {
        val limit =
            assertThrows(IllegalStateException::class.java) {
                NimProtocol.parse("""{"choices":[{"message":{"content":"partial"},"finish_reason":"length"}]}""")
            }
        assertEquals(true, limit.message!!.contains("max_tokens"))
        assertThrows(IllegalStateException::class.java) {
            NimProtocol.parse("""{"choices":[{"message":{"content":null,"reasoning_content":"thinking"}}]}""")
        }
    }

    @Test
    fun `URL accepts host version and complete endpoint without double v1`() {
        val expected = "https://integrate.api.nvidia.com/v1/chat/completions"
        listOf("https://integrate.api.nvidia.com/", "https://integrate.api.nvidia.com/v1/", expected).forEach {
            assertEquals(expected, NimProtocol.endpoint(it))
        }
        assertThrows(IllegalArgumentException::class.java) { NimProtocol.endpoint("https://user:secret@example.test/v1") }
    }

    @Test
    fun `stale mixed case Accept cannot re-enable SSE`() {
        val headers = NimProtocol.headers(mapOf("accept" to "text/event-stream", "Accept" to "text/event-stream", "Authorization" to "Bearer test"))
        assertEquals(1, headers.keys.count { it.equals("accept", true) })
        assertEquals("application/json", headers["Accept"])
        assertEquals("Bearer test", headers["Authorization"])
    }

    @Test
    fun `reasoning budget leaves room for the answer and foreign models keep defaults`() {
        val payload = mutableMapOf<String, Any?>()
        NimProtocol.applyReasoning(payload, NvidiaNimOptions.DEFAULT_MODEL, NvidiaNimOptions(reasoningEffort = "high"), 100)
        assertEquals(99, payload["reasoning_budget"])
        val foreign = mutableMapOf<String, Any?>()
        NimProtocol.applyReasoning(foreign, "meta/llama-3.1-8b-instruct", NvidiaNimOptions(), 100)
        assertFalse(foreign.containsKey("reasoning_effort"))
    }

    @Test
    fun `Retry After accepts delta seconds and HTTP date and rejects malformed values`() {
        assertEquals(12_000L, NimProtocol.retryAfterMs("12"))
        assertEquals(60_000L, NimProtocol.retryAfterMs("Wed, 21 Oct 2015 07:28:00 GMT", 1445412420000))
        assertEquals(null, NimProtocol.retryAfterMs("invalid"))
    }
}
