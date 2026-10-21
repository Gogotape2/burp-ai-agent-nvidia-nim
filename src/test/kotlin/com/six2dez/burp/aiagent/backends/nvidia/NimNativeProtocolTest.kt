package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.core.JsonProcessingException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NimNativeProtocolTest {
    @Test
    fun bufferedSseAssemblesArgumentsBeforeExposingACall() {
        val body =
            """
data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_sse","function":{"name":"scope_check","arguments":"{\"url\":"}}]}}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"https://example.test/\"}"}}]},"finish_reason":"tool_calls"}]}

data: [DONE]

            """.trimIndent()
        val completion = NimProtocol.parse(body)
        assertEquals("call_sse", completion.calls.single().id)
        assertEquals("""{"url":"https://example.test/"}""", completion.calls.single().argumentsJson)
        assertThrows(IllegalArgumentException::class.java) { NimProtocol.parse(body.substringBefore("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\"")) }
    }

    @Test
    fun normalAnswerAllowsAnEmptyCallArrayAndMissingIdsAreAssignedLocally() {
        assertTrue(NimProtocol.parse("""{"choices":[{"message":{"content":"answer","tool_calls":[]},"finish_reason":"stop"}]}""").calls.isEmpty())
        val calls = NimNativeTools.parse(NimProtocol.mapper.readTree("""[{"function":{"name":"status","arguments":""}}]"""))
        assertFalse(calls.single().id.isBlank())
        assertEquals("{}", calls.single().argumentsJson)
    }

    @Test
    fun invalidArgumentTypesAndTrailingJsonDataAreRejected() {
        val invalidType = NimProtocol.mapper.readTree("""[{"id":"call_object","function":{"name":"status","arguments":{}}}]""")
        assertThrows(IllegalArgumentException::class.java) { NimNativeTools.parse(invalidType) }
        val trailing = NimProtocol.mapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>(listOf(mapOf("id" to "call_trailing", "function" to mapOf("name" to "status", "arguments" to "{} {}"))))
        assertThrows(JsonProcessingException::class.java) { NimNativeTools.parse(trailing) }
        val response = """{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]} {}"""
        assertThrows(JsonProcessingException::class.java) { NimProtocol.parse(response) }
    }

    @Test
    fun duplicateIdsAndOversizedArgumentObjectsAreRejected() {
        val call = """{"id":"call_same","type":"function","function":{"name":"status","arguments":"{}"}}"""
        assertThrows(IllegalArgumentException::class.java) { NimNativeTools.parse(NimProtocol.mapper.readTree("[$call,$call]")) }
        val longArgs = NimProtocol.mapper.writeValueAsString(mapOf("input" to "x".repeat(260_000)))
        val node = NimProtocol.mapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>(listOf(mapOf("id" to "call_long", "function" to mapOf("name" to "status", "arguments" to longArgs))))
        assertThrows(IllegalArgumentException::class.java) { NimNativeTools.parse(node) }
    }
}
