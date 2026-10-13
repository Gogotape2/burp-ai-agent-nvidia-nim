package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
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
        whenever(
            recording.api
                .burpSuite()
                .version()
                .edition(),
        ).thenReturn(BurpSuiteEdition.PROFESSIONAL)
    }

    private val registry = BackendRegistry(recording.api)

    private val supervisor = AgentSupervisor(recording.api, registry, mock<AuditLogger>(), StoreAiAccessPolicy())

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

    @Test
    fun aiPassiveScanWithUseAiOffIsRefusedBeforeTheScannerIsAsked() {
        recording.aiEnabled.set(false)
        val scanner = mock<PassiveAiScanner>()

        val result = McpToolExecutor.executeToolResult("ai_passive_scan", "{}", context(passiveScanner = scanner))

        assertEquals(true, result.isError, "a refused AI tool must be an MCP tool error")
        assertEquals(storeRefusal, textOf(result), "the refusal text is the store policy's, verbatim")
        verify(scanner, never()).manualScan(any(), any())
        assertEquals(0, recording.sendCount(), "no provider request may leave Burp while Use AI is off")
        verify(recording.api.logging(), never()).logToError(any<Throwable>())
    }

    @Test
    fun theToolListIsTheSameWithUseAiOnAndOff() {
        recording.aiEnabled.set(true)
        val withUseAiOn = McpToolExecutor.describeTools(context(), includeSchemas = false)
        recording.aiEnabled.set(false)
        val withUseAiOff = McpToolExecutor.describeTools(context(), includeSchemas = false)

        assertEquals(withUseAiOn, withUseAiOff, "D-03: the tool list must not change with Use AI")
        AI_TOOL_IDS.forEach { id ->
            assertTrue(withUseAiOff.lines().any { it.startsWith("- $id: ") }, "$id must stay listed while Use AI is off")
        }
    }

    @Test
    fun toolsThatSendNoAiRequestAreNotGatedByUseAi() {
        recording.aiEnabled.set(false)
        val calls =
            mapOf(
                "status" to "{}",
                "redact_preview" to """{"text":"secret@example.com","mode":"STRICT"}""",
                "ai_backends_list" to "{}",
            )

        calls.forEach { (tool, args) ->
            val result = McpToolExecutor.executeToolResult(tool, args, context())
            val text = textOf(result)
            assertNotEquals(true, result.isError, "$tool must not be an MCP error while Use AI is off, got: $text")
            assertNotEquals(storeRefusal, text, "$tool must not carry the AI refusal")
            assertNotEquals(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI, text, "$tool must not carry the AI refusal")
        }
    }

    @Test
    fun theGateIsReadOnEveryCallSoTurningUseAiOffRefusesTheNextCall() {
        recording.aiEnabled.set(true)
        val first = McpToolExecutor.executeToolResult("ai_analyze", """{"text":"x"}""", context())
        assertNotEquals(storeRefusal, textOf(first), "with Use AI on the first call is not refused")

        recording.aiEnabled.set(false)
        val next = McpToolExecutor.executeToolResult("ai_analyze", """{"text":"x"}""", context())

        assertEquals(true, next.isError, "D-04: the call after Use AI turns off is refused")
        assertEquals(storeRefusal, textOf(next))
        assertEquals(0, recording.sendCount(), "no provider request left Burp on either call")
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun context(passiveScanner: PassiveAiScanner? = null): McpToolContext =
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
            passiveScanner = passiveScanner,
            backendRegistry = registry,
        )

    private fun textOf(result: CallToolResult): String = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }

    private companion object {
        val AI_TOOL_IDS = listOf("ai_analyze", "ai_passive_scan")
    }
}
