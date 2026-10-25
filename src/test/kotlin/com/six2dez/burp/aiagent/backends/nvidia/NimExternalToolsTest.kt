package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.FunctionCall
import com.six2dez.burp.aiagent.backends.FunctionResult
import com.six2dez.burp.aiagent.backends.FunctionTool
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NimExternalToolsTest {
    @Test
    fun namesAreProtocolSafeAndRoundTripWithTheOriginalCallId() {
        val name = "ext:fixture:search.database"
        val tool = FunctionTool(name, "Search", """{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}""")
        val wire = NimNativeTools.wireName(name)
        assertTrue(wire.matches(Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}")))
        assertNotEquals(wire, NimNativeTools.wireName("ext:other:search.database"))
        val definitions = NimProtocol.mapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>(NimNativeTools.definitions(listOf(tool)))
        assertEquals(wire, definitions[0]["function"]["name"].asText())
        assertEquals("q", definitions[0]["function"]["parameters"]["required"][0].asText())
        val session = NimNativeSession()
        val request = AgentChatRequest("chat", "nvidia-nim", "search", traceId = "trace", tools = listOf(tool))
        session.prepare(request, listOf(mapOf("role" to "user", "content" to "search")))
        val call = session.accept(NimProtocol.Completion("", null, listOf(FunctionCall("call_ext", wire, """{"q":"test"}"""))))!!
        assertEquals(name, call.name)
        assertEquals("call_ext", call.id)
        val next = session.prepare(request.copy(previousToolResult = FunctionResult(call.id, "result")), emptyList())
        val messages = NimProtocol.mapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>(next.messages)
        assertEquals(wire, messages[1]["tool_calls"][0]["function"]["name"].asText())
        assertEquals("call_ext", messages[2]["tool_call_id"].asText())
    }
}
