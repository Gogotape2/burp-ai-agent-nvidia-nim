package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.full.FullAiAccessPolicy
import com.six2dez.burp.aiagent.resolveAiAccessPolicy
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.Plugins
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Regression tests for the v0.6.0 -> v0.6.x bug where Burp Pro's "Use AI" toggle was incorrectly
 * gating ALL backends — including CLI agents (claude-cli, codex-cli, gemini-cli, …) and HTTP
 * backends (ollama, lmstudio, openai-compatible, nvidia-nim, perplexity) that have nothing to do
 * with Burp's bundled AI. In the full build the toggle must only affect the `burp-ai` backend.
 *
 * Phase 29 / BUILD-04: that rule is the full build's [FullAiAccessPolicy], so this suite lives in
 * fullTest and drives a real [AgentSupervisor] with it. The BApp Store build's stricter rule is
 * pinned by StoreAiAccessPolicyTest in the store suite.
 */
class BurpAiGateScopingTest {
    @Test
    fun fullClasspathResolvesTheFullPolicyThroughServiceLoader() {
        val conflicts = mutableListOf<List<String>>()
        val policy = resolveAiAccessPolicy { conflicts += it }
        assertTrue(policy is FullAiAccessPolicy, "full classpath must resolve FullAiAccessPolicy, got ${policy.javaClass.name}")
        assertTrue(conflicts.isEmpty(), "exactly one provider expected, got conflicts $conflicts")
        assertEquals(
            listOf(FullAiAccessPolicy::class.java.name),
            Plugins.load(AiAccessPolicy::class.java).map { it.javaClass.name },
        )
    }

    @Test
    fun onlyBurpAiIsRefusedWhenToggleOff() {
        val supervisor = newSupervisor(burpAiEnabled = false)

        // The Burp-AI backend must surface the gate when the toggle is off, with the 1.0.1 message.
        assertEquals(
            "Burp AI is disabled in Burp Suite settings. Enable 'Use AI' for extensions, or pick a different backend.",
            supervisor.aiAccessRefusal("burp-ai"),
        )

        // Every other backend must be unaffected: the gate is irrelevant for them.
        OTHER_BACKENDS.forEach { backendId ->
            assertNull(
                supervisor.aiAccessRefusal(backendId),
                "$backendId must not be gated by Burp's Use AI toggle",
            )
        }
    }

    @Test
    fun everyBackendIsAllowedWhenToggleOn() {
        val supervisor = newSupervisor(burpAiEnabled = true)

        assertNull(supervisor.aiAccessRefusal("burp-ai"))
        OTHER_BACKENDS.forEach { backendId ->
            assertNull(supervisor.aiAccessRefusal(backendId), "$backendId must be allowed while 'Use AI' is on")
        }
    }

    @Test
    fun startOrAttachRefusesBurpAiWithThePolicyMessage() {
        val supervisor = newSupervisor(burpAiEnabled = false)

        assertFalse(supervisor.startOrAttach("burp-ai"))
        assertNotNull(supervisor.lastStartError())
        assertEquals(supervisor.aiAccessRefusal("burp-ai"), supervisor.lastStartError())
    }

    @Test
    fun isBlockedByAiAccessPolicyReturnsFalseWhenNoBackendIsRunning() {
        val supervisor = newSupervisor(burpAiEnabled = false)

        // No active session yet -> the scanner gate must not short-circuit. The send() path will
        // surface the precise error if/when the user actually starts a burp-ai session.
        assertFalse(supervisor.isBlockedByAiAccessPolicy())
    }

    @Test
    fun isAiEnabledStillReportsRawBurpPreference() {
        assertEquals(true, newSupervisor(burpAiEnabled = true).isAiEnabled())
        assertEquals(false, newSupervisor(burpAiEnabled = false).isAiEnabled())
    }

    /** Phase 31 / D-11 — the full build keeps its startup check and local-backend polling. */
    @Test
    fun theFullPolicyAllowsUnpromptedHealthChecks() {
        assertTrue(FullAiAccessPolicy().allowsUnpromptedHealthChecks())
        assertTrue(resolveAiAccessPolicy().allowsUnpromptedHealthChecks(), "the ServiceLoader-resolved policy")
        assertTrue(newSupervisor(burpAiEnabled = false).allowsUnpromptedHealthChecks(), "the supervisor delegates")
        assertTrue(newSupervisor(burpAiEnabled = true).allowsUnpromptedHealthChecks())
    }

    private fun newSupervisor(burpAiEnabled: Boolean): AgentSupervisor {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.ai().isEnabled()).thenReturn(burpAiEnabled)
        return AgentSupervisor(
            api = api,
            registry = BackendRegistry(api),
            audit = mock<AuditLogger>(),
            aiAccessPolicy = FullAiAccessPolicy(),
        )
    }

    private companion object {
        val OTHER_BACKENDS =
            listOf(
                "claude-cli",
                "codex-cli",
                "gemini-cli",
                "opencode-cli",
                "copilot-cli",
                "ollama",
                "lmstudio",
                "openai-compatible",
                "nvidia-nim",
                "perplexity",
                "anthropic",
            )
    }
}
