package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.core.JsonProcessingException
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.FunctionTool
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NimTextToolsTest {
    private val call = """{"tool":"scope_check","args":{"url":"https://example.test/"}}"""

    @Test
    fun concatenatedUserPayloadIsDecodedAsACompleteOrderedBatch() {
        val history = """{"tool":"proxy_http_history","args":{"count":20,"includeUnpreprocessedResponse":false,"offset":0}}"""
        val search = """{"tool":"response_body_search","args":{"count":10,"offset":0,"regex":"jquery.min.js","scopeOnly":false}}"""
        val calls = NimTextTools.parse(history + search)!!
        assertEquals(listOf("proxy_http_history", "response_body_search"), calls.map { it.name })
        assertEquals(2, calls.map { it.id }.distinct().size)
        assertEquals(
            "jquery.min.js",
            NimProtocol.mapper
                .readTree(calls[1].argumentsJson)
                .path("regex")
                .asText(),
        )
    }

    @Test
    fun arraysAndSoleFencesPreserveQuotedBracesInArguments() {
        val value = "literal }{ with \"quoted\" text"
        val encoded = NimProtocol.mapper.writeValueAsString(mapOf("tool" to "scope_check", "args" to mapOf("url" to value)))
        for (payload in listOf("[$encoded,$call]", "```json\n$encoded$call\n```")) {
            val parsed = NimTextTools.parse(payload)!!
            assertEquals(2, parsed.size)
            assertEquals(
                value,
                NimProtocol.mapper
                    .readTree(parsed[0].argumentsJson)
                    .path("url")
                    .asText(),
            )
        }
    }

    @Test
    fun reportsAndMixedProseNeverExposeAnyBatchMember() {
        val report = """{"name":"Finding","severity":"High"}"""
        for (payload in listOf("Example: $call", "$call\nDone", "$call$report", "[$call,$report]", "```json\n$call\n```\nExplanation", report)) {
            assertNull(NimTextTools.parse(payload), payload)
        }
    }

    @Test
    fun malformedOrIncompleteLaterMembersCannotCausePartialExecution() {
        assertNull(NimTextTools.parse(call + """{"tool":"scope_check","args":{"url":"unfinished"""))
        assertThrows(IllegalArgumentException::class.java) { NimTextTools.parse(call + """{"tool":"scope_check","args":[]}""") }
        val trailing = NimProtocol.mapper.writeValueAsString(mapOf("tool" to "scope_check", "arguments" to "{} {}"))
        assertThrows(JsonProcessingException::class.java) { NimTextTools.parse(trailing) }
    }

    @Test
    fun batchesHaveAWholeTurnAndCallCountLimit() {
        assertThrows(IllegalArgumentException::class.java) { NimTextTools.parse((1..17).joinToString("") { call }) }
        assertNull(NimTextTools.parse(" ".repeat(1_000_001) + call + "x".repeat(1_000_001)))
    }

    @Test
    fun disabledToolsAndStructuredOutputRemainData() {
        val completion = NimProtocol.Completion(call, null)
        val request = AgentChatRequest("chat", "nvidia-nim", "Read synthetic data")
        val events = mutableListOf<AgentTurnEvent>()
        assertSame(completion, NimTextTools.recover(completion, request, true, events::add))
        val enabled = request.copy(tools = listOf(FunctionTool("scope_check", "Scope", "{}")), jsonMode = true)
        assertSame(completion, NimTextTools.recover(completion, enabled, true, events::add))
        assertTrue(events.isEmpty())
    }

    @Test
    fun anUnadvertisedMemberRejectsTheEntireRecoveryBeforeAnyCallEvent() {
        val events = mutableListOf<AgentTurnEvent>()
        val request = AgentChatRequest("chat", "nvidia-nim", "Read", tools = listOf(FunctionTool("scope_check", "Scope", "{}")))
        val completion = NimProtocol.Completion(call + """{"tool":"unavailable","args":{}}""", null)
        assertThrows(IllegalArgumentException::class.java) { NimTextTools.recover(completion, request, true, events::add) }
        assertTrue(events.isEmpty())
    }
}
