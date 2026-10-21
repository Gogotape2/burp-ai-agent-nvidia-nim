package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ToolCallParserTest {
    @Test
    fun `extracts direct tool payload`() {
        val payload = """{"tool":"status","args":{}}"""
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("status", call?.tool)
        assertEquals("{}", call?.argsJson)
    }

    @Test
    fun `extracts fenced json tool payload`() {
        val payload =
            """
            ```json
            {"name":"proxy_http_history","arguments":{"limit":5}}
            ```
            """.trimIndent()
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("proxy_http_history", call?.tool)
        assertEquals("""{"limit":5}""", call?.argsJson)
    }

    @Test
    fun `extracts openai style tool_calls payload`() {
        val payload =
            """
            {
              "choices": [
                {
                  "message": {
                    "tool_calls": [
                      {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                          "name": "http1_request",
                          "arguments": "{\"targetHostname\":\"example.com\",\"targetPort\":443}"
                        }
                      }
                    ]
                  }
                }
              ]
            }
            """.trimIndent()
        val call = ToolCallParser.extractFirst(payload)
        assertNotNull(call)
        assertEquals("http1_request", call?.tool)
        assertTrue(call?.argsJson?.contains("targetHostname") == true)
    }

    @Test
    fun `does not execute json embedded in prose`() {
        val payload = "Let me call this tool now: {\"tool\":\"scope_check\",\"args\":{\"url\":\"https://target.test\"}} and continue."
        assertNull(ToolCallParser.extractFirst(payload))
    }

    @Test
    fun `issue names and report examples are not tool calls`() {
        val issue = """{"name":"Authentication Bypass: Login Accepts Arbitrary Credentials","severity":"High","evidence":"unverified"}"""
        val example = """{"tool":"http1_request","args":{"targetHostname":"example.test"}}"""
        for (report in listOf(issue, "```json\n$issue\n```", "PoC example:\n```json\n$example\n```", """{"name":"status"}""", """{"tool":123,"args":{}}""")) {
            assertNull(ToolCallParser.extractFirst(report), report)
        }
    }

    @Test
    fun `unknown explicit call remains available for diagnostic handling`() {
        assertEquals("missing_tool", ToolCallParser.extractFirst("""{"tool":"missing_tool","args":{}}""")?.tool)
    }

    @Test
    fun `returns null when no tool call exists`() {
        val payload = "I will analyze and then provide a final answer without using any tool."
        val call = ToolCallParser.extractFirst(payload)
        assertNull(call)
    }
}
