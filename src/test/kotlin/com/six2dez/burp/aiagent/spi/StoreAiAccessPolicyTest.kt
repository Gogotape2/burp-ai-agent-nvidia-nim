package com.six2dez.burp.aiagent.spi

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 29 / BUILD-04 (T-29-14) — the BApp Store build's AI access policy. While Burp's "Use AI"
 * setting is off, a request to ANY backend is refused; while it is on, every backend is allowed.
 *
 * The truth table covers every backend id the core registers, plus an id no backend uses, so a new
 * or misspelled id cannot slip through a hardcoded allow-list.
 */
class StoreAiAccessPolicyTest {
    private val policy = StoreAiAccessPolicy()

    @Test
    fun everyBackendIsRefusedWhileBurpAiIsDisabled() {
        BACKEND_IDS.forEach { backendId ->
            val refusal = policy.refusal(backendId, burpAiEnabled = false)
            assertNotNull(refusal, "$backendId must be refused while Burp's 'Use AI' setting is off")
            assertFalse(refusal.isNullOrBlank(), "$backendId: the refusal must carry a user-facing message")
        }
    }

    @Test
    fun everyBackendIsAllowedWhileBurpAiIsEnabled() {
        BACKEND_IDS.forEach { backendId ->
            assertNull(policy.refusal(backendId, burpAiEnabled = true), "$backendId must be allowed while 'Use AI' is on")
        }
    }

    @Test
    fun refusalTellsTheUserToTurnOnBurpsUseAiSetting() {
        val refusal = policy.refusal("ollama", burpAiEnabled = false).orEmpty()
        assertTrue(refusal.contains("'Use AI'"), "the refusal must name the setting to change: $refusal")
    }

    private companion object {
        val BACKEND_IDS =
            listOf(
                "burp-ai",
                "ollama",
                "lmstudio",
                "openai-compatible",
                "nvidia-nim",
                "perplexity",
                "anthropic",
                "some-unknown-backend",
            )
    }
}
