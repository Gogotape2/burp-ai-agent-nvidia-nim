package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Phase 31 / D-03, SC1 (MCP rows) — the MCP AI tools under the BApp Store policy, with a REAL
 * [AgentSupervisor] built on [StoreAiAccessPolicy] and a [RecordingMontoya] that counts every provider
 * request that reaches `Http.sendRequest`.
 *
 * While Burp's "Use AI" is off, a tool whose descriptor carries `requiresBurpAi` is refused by the
 * executor before its handler runs: the result is an MCP tool error (`isError = true`) whose text is the
 * store policy's refusal, verbatim, nothing is sent to any provider, and no stack trace is logged.
 */
class McpAiToolRefusalTest {
    private val recording = RecordingMontoya()

    init {
        whenever(recording.api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
    }

    private val supervisor =
        AgentSupervisor(recording.api, BackendRegistry(recording.api), mock<AuditLogger>(), StoreAiAccessPolicy())

    private val storeRefusal: String = requireNotNull(StoreAiAccessPolicy().refusal("burp-ai", false))

    @AfterEach
    fun restoreFactory() {
        recording.close()
    }

    @Test
    fun aiAnalyzeWithUseAiOffIsAnMcpErrorCarryingTheStoreRefusalAndSendsNothing() {
        recording.aiEnabled.set(false)

        val result = McpToolExecutor.executeToolResult("ai_analyze", """{"text":"x"}""", context())

        assertEquals(true, result.isError, "a refused AI tool must be an MCP tool error")
        assertEquals(storeRefusal, textOf(result), "the refusal text is the store policy's, verbatim")
        assertEquals(0, recording.sendCount(), "no provider request may leave Burp while Use AI is off")
        verify(recording.api.logging(), never()).logToError(any<Throwable>())
        verify(recording.api.logging(), never()).logToError(any<String>(), any<Throwable>())
    }

    @Test
    fun aiAnalyzeWithUseAiOnIsNotRefused() {
        recording.aiEnabled.set(true)

        val result = McpToolExecutor.executeToolResult("ai_analyze", """{"text":"x"}""", context())

        // No backend session runs in this fixture, so the call proceeds to supervisor.send and comes
        // back with the send path's own answer; the point is that the AI gate did not refuse it.
        assertNotEquals(storeRefusal, textOf(result), "with Use AI on the call must proceed past the gate")
        assertNotEquals(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI, textOf(result))
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun context(): McpToolContext =
        McpToolContext(
            api = recording.api,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
            supervisor = supervisor,
        )

    private fun textOf(result: CallToolResult): String =
        result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
}
