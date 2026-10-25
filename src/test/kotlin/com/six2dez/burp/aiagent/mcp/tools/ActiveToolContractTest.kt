package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.context.ChatContextStore
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

class ActiveToolContractTest {
    private fun context() =
        McpToolContext(
            mock<MontoyaApi>(),
            PrivacyMode.OFF,
            false,
            "fixture",
            McpToolCatalog.all().associate { it.id to true },
            true,
            McpToolCatalog.unsafeToolIds(),
            emptySet(),
            McpRequestLimiter(2),
            BurpSuiteEdition.PROFESSIONAL,
            32768,
            activeRuntime = mock<McpActiveRuntime>(),
            chatContextStore = ChatContextStore(),
        )

    @Test
    fun privacyRedactsEmbeddedHeadersBeforeJsonEscapingAndPreservesLocalHandles() {
        val context = context().copy(privacyMode = PrivacyMode.BALANCED)
        val value =
            kotlinx.serialization.json.buildJsonObject {
                put("request", kotlinx.serialization.json.JsonPrimitive("GET / HTTP/1.1\r\nAuthorization: Bearer sensitive-fixture-value\r\nCookie: session=sensitive-cookie-value\r\n\r\n"))
                put("attackId", kotlinx.serialization.json.JsonPrimitive("attack_12345678-1234-1234-1234-123456789abc"))
                put("connectionId", kotlinx.serialization.json.JsonPrimitive("ws_12345678-1234-1234-1234-123456789abc"))
            }
        val redacted = redactActiveToolResult(value, context).toString()
        assertFalse(redacted.contains("sensitive-fixture-value"))
        assertFalse(redacted.contains("sensitive-cookie-value"))
        assertTrue(redacted.contains("attack_12345678-1234-1234-1234-123456789abc"))
        assertTrue(redacted.contains("ws_12345678-1234-1234-1234-123456789abc"))
    }

    @Test
    fun everyNewToolIsRegisteredAndAdvertisedWithAnInitializedRuntime() {
        val context = context()
        val functions = McpToolExecutor.functionTools(context).map { it.name }.toSet()
        assertTrue(functions.containsAll(ActiveToolHandlers.ids))
        assertTrue(McpToolRegistrations.allIds().containsAll(ActiveToolHandlers.ids))
        ActiveToolHandlers.ids.forEach { assertTrue(context.unavailableReason(it) == null) }
        val unavailable = context.copy(activeRuntime = null)
        assertTrue(McpToolExecutor.functionTools(unavailable).none { it.name in ActiveToolHandlers.ids })
        assertTrue(ActiveToolHandlers.ids.all { unavailable.unavailableReason(it)!!.contains("not initialized") })
    }

    @Test
    fun schemasAdvertiseRealRuntimeLimitsAndNestedPositionFields() {
        val start = McpToolExecutor.inputSchema("intruder_attack_start")
        assertEquals(
            "1000",
            start.properties
                .getValue("maxRequests")
                .jsonObject
                .getValue("maximum")
                .jsonPrimitive.content,
        )
        assertEquals(
            "5",
            start.properties
                .getValue("concurrency")
                .jsonObject
                .getValue("maximum")
                .jsonPrimitive.content,
        )
        assertEquals(
            "120000",
            start.properties
                .getValue("timeoutMs")
                .jsonObject
                .getValue("maximum")
                .jsonPrimitive.content,
        )
        val item =
            start.properties
                .getValue("positions")
                .jsonObject
                .getValue("items")
                .jsonObject
        assertTrue(
            item
                .getValue("properties")
                .jsonObject.keys
                .containsAll(listOf("marker", "payloads", "baseValue")),
        )
        assertFalse(
            McpToolExecutor
                .inputSchema("websocket_send")
                .required
                .orEmpty()
                .contains("text"),
        )
        assertEquals(
            "30000",
            McpToolExecutor
                .inputSchema("websocket_receive")
                .properties
                .getValue("waitMs")
                .jsonObject
                .getValue("maximum")
                .jsonPrimitive.content,
        )
    }

    @Test
    fun activeCapabilitiesStillRequireTheirConfiguredPermission() {
        val context = context().copy(unsafeEnabled = false)
        listOf("intruder_attack_start", "websocket_open", "websocket_send").forEach { name ->
            assertTrue(McpToolExecutor.executeToolResult(name, "{}", context).isError == true)
            assertTrue(context.unavailableReason(name)!!.contains("unsafe"))
        }
    }
}
