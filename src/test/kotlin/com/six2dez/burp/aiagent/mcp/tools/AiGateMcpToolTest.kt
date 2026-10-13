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
 * The AI gate on MCP tools, seen through the chat `/tool` path ([McpToolExecutor.executeTool]).
 *
 * Phase 31 / D-03, D-16: the gate is the executor's, not the handlers'. A descriptor flagged
 * `requiresBurpAi` (ai_analyze, ai_passive_scan) is refused before its handler runs whenever
 * `AgentSupervisor.aiToolRefusal()` answers a refusal, and the refusal comes back as an MCP tool error
 * carrying that text. The supervisor here is a mock, so the two gated tests stub `aiToolRefusal()` with
 * the 1.0.1 text ([AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI]); McpAiToolRefusalTest drives a real
 * supervisor and counts the provider requests. A tool that sends no AI request (redact_preview) is not
 * gated.
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
        whenever(supervisor.aiToolRefusal()).thenReturn(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI)

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
        whenever(supervisor.aiToolRefusal()).thenReturn(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI)

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
        )
}
