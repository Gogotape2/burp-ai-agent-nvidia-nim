package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.full.FullAiAccessPolicy
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
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
 * Phase 31 / D-16, GATE-04 — the MCP AI tools in the full (GitHub) build, with a REAL [AgentSupervisor]
 * on [FullAiAccessPolicy] and a [RecordingMontoya] that counts every provider request.
 *
 * The full policy refuses only `burp-ai` while Burp's "Use AI" is off, but `ai_analyze` and
 * `ai_passive_scan` keep their 1.0.1 rule of requiring "Use AI" whatever the backend. That rule comes
 * from data (the descriptors' `requiresBurpAi` flag, applied by the executor on top of the backend
 * policy through `AgentSupervisor.aiToolRefusal`), not from a flavor branch: with Ollama saved and
 * "Use AI" off both tools are MCP errors carrying [AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI]; with
 * burp-ai saved the policy's own text wins; with "Use AI" on neither is refused.
 */
class FullMcpAiToolGateTest {
    private val recording = RecordingMontoya()

    init {
        whenever(
            recording.api
                .burpSuite()
                .version()
                .edition(),
        ).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(recording.api.proxy().history()).thenReturn(emptyList())
    }

    private val registry = BackendRegistry(recording.api)

    private val supervisor = AgentSupervisor(recording.api, registry, mock<AuditLogger>(), FullAiAccessPolicy())

    private val scanner = mock<PassiveAiScanner>()

    @AfterEach
    fun restoreFactory() {
        recording.close()
    }

    @Test
    fun ollamaSavedAndUseAiOffRefusesBothAiToolsWithThe101Text() {
        supervisor.applySettings(TestSettings.baselineSettings("ollama"))
        recording.aiEnabled.set(false)

        AI_TOOLS.forEach { (tool, args) ->
            val result = McpToolExecutor.executeToolResult(tool, args, context())
            assertEquals(true, result.isError, "$tool must be an MCP error while Use AI is off, whatever the backend")
            assertEquals(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI, textOf(result), "$tool carries the 1.0.1 text")
        }
        verify(scanner, never()).manualScan(any(), any())
        assertEquals(0, recording.sendCount(), "no provider request may leave Burp")
    }

    @Test
    fun burpAiSavedAndUseAiOffRefusesBothAiToolsWithThePolicyText() {
        supervisor.applySettings(TestSettings.baselineSettings("burp-ai"))
        recording.aiEnabled.set(false)
        val policyText = requireNotNull(FullAiAccessPolicy().refusal("burp-ai", false))

        AI_TOOLS.forEach { (tool, args) ->
            val result = McpToolExecutor.executeToolResult(tool, args, context())
            assertEquals(true, result.isError, "$tool must be an MCP error")
            assertEquals(policyText, textOf(result), "$tool carries the full policy's burp-ai refusal")
        }
        verify(scanner, never()).manualScan(any(), any())
        assertEquals(0, recording.sendCount(), "no provider request may leave Burp")
    }

    @Test
    fun useAiOnRefusesNeitherAiTool() {
        recording.aiEnabled.set(true)
        val refusals =
            setOf(
                AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI,
                requireNotNull(FullAiAccessPolicy().refusal("burp-ai", false)),
            )

        listOf("ollama", "burp-ai").forEach { saved ->
            supervisor.applySettings(TestSettings.baselineSettings(saved))
            AI_TOOLS.forEach { (tool, args) ->
                val text = textOf(McpToolExecutor.executeToolResult(tool, args, context()))
                assertEquals(false, text in refusals, "$tool with $saved saved and Use AI on must not be refused, got: $text")
                assertNotEquals("", text)
            }
        }
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
            passiveScanner = scanner,
            backendRegistry = registry,
        )

    private fun textOf(result: CallToolResult): String = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }

    private companion object {
        val AI_TOOLS =
            listOf(
                "ai_analyze" to """{"text":"x"}""",
                "ai_passive_scan" to "{}",
            )
    }
}
