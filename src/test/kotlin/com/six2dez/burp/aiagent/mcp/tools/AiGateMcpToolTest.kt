package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Wave-0 stub tests for the AI gate on MCP tools.
 * aiAnalyze_returnsErrorWhenIsEnabledFalse and aiPassiveScan_returnsErrorWhenIsEnabledFalse
 * will fail red until Wave 2 implements the ai_analyze and ai_passive_scan handlers.
 * aiAnalyze_doesNotGateNonAiTool will fail red until Wave 2 implements redact_preview.
 *
 * Every `executeTool` call below declares [ToolCallOrigin.UserSlashCommand]. These tests exercise the
 * EXECUTOR, not the SEC-06 gate: the origin is a declaration the type system requires (plan 22-07), not
 * a behaviour switch, and no assertion here depends on which variant is passed.
 */
class AiGateMcpToolTest {
    @Test
    fun aiAnalyze_returnsErrorWhenIsEnabledFalse() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val supervisor = mock<AgentSupervisor>()
        whenever(supervisor.isAiEnabled()).thenReturn(false)
        whenever(supervisor.requiresBurpAiAndDisabled("burp-ai")).thenReturn(true)

        val context = buildContext(api, supervisor)
        val result = McpToolExecutor.executeTool("ai_analyze", """{"text":"test"}""", context, ToolCallOrigin.UserSlashCommand)

        assertTrue(
            result.contains("unavailable", ignoreCase = true),
            "Gate must return unavailable message when AI is disabled, got: $result",
        )
    }

    @Test
    fun aiPassiveScan_returnsErrorWhenIsEnabledFalse() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val supervisor = mock<AgentSupervisor>()
        whenever(supervisor.isAiEnabled()).thenReturn(false)
        whenever(supervisor.requiresBurpAiAndDisabled("burp-ai")).thenReturn(true)

        val context = buildContext(api, supervisor)
        val result = McpToolExecutor.executeTool("ai_passive_scan", """{}""", context, ToolCallOrigin.UserSlashCommand)

        assertTrue(
            result.contains("unavailable", ignoreCase = true),
            "ai_passive_scan must check AI gate before using passiveScanner, got: $result",
        )
    }

    @Test
    fun aiAnalyze_doesNotGateNonAiTool() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(false)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)

        val context = buildContext(api, supervisor = null)
        val result =
            McpToolExecutor.executeTool(
                "redact_preview",
                """{"text":"secret@example.com","mode":"STRICT"}""",
                context,
                ToolCallOrigin.UserSlashCommand,
            )

        assertFalse(
            result.contains("unavailable", ignoreCase = true),
            "redact_preview must not be gated by AI toggle, got: $result",
        )
    }

    private fun buildContext(
        api: MontoyaApi,
        supervisor: AgentSupervisor?,
    ): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 1024,
            supervisor = supervisor,
            aiBackendId = "burp-ai",
        )
}
