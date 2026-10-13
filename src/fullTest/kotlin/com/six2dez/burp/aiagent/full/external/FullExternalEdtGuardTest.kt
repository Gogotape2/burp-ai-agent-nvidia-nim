package com.six2dez.burp.aiagent.full.external

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.InvocationTargetException
import javax.swing.SwingUtilities

/**
 * REL-05 / F-4, full build half (Phase 29 / NET-02, D-14). The store half is McpToolExecutorEdtGuardTest.
 *
 * In the full build the production registry carries [ExternalToolProvider] (loaded from the src/full
 * `ToolProvider` services file) with no manager wired, exactly as 1.0.1 shipped: an `ext:` call off the
 * EDT returns 1.0.1's "External MCP client not available", and the same call on the EDT is refused by the
 * executor's REL-05 door before the provider is consulted.
 */
class FullExternalEdtGuardTest {
    private fun context(): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
        )
    }

    @Test
    fun theProductionRegistryCarriesTheExternalProvider() {
        assertTrue(
            McpToolCatalog.registry.providers().any { it is ExternalToolProvider },
            "the full build's ToolProvider services file lists ExternalToolProvider",
        )
    }

    @Test
    fun offTheEdtAnExtCallReturnsThe101ClientNotAvailableResult() {
        val result = McpToolExecutor.executeToolResult("ext:demo:search", """{"q":"x"}""", context())

        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text?.toString().orEmpty() }
        assertTrue(result.isError == true, "Got: $text")
        assertEquals("External MCP client not available", text, "1.0.1 parity: the manager is not wired")
        assertFalse(text.contains("REL-05"), "the guard does not fire off the EDT")
    }

    @Test
    fun onTheEdtAnExtCallIsRefusedBeforeTheProvider() {
        val context = context()
        var thrown: Throwable? = null
        try {
            SwingUtilities.invokeAndWait {
                McpToolExecutor.executeToolResult("ext:demo:search", """{"q":"x"}""", context)
            }
        } catch (e: InvocationTargetException) {
            thrown = e.cause ?: e
        }

        assertInstanceOf(IllegalStateException::class.java, thrown, "REL-05: refused on the EDT. Thrown was: $thrown")
        assertTrue(thrown?.message.orEmpty().contains("REL-05"), "Message was: ${thrown?.message}")
    }

    @Test
    fun anExtNameStaysConfirmEachInTheFullBuild() {
        // ADR-11 / T-29-30: an external server's tools are untrusted, including a name that shadows a built-in.
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor("ext:x:scope_check"))
    }
}
