package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 31 / D-01, D-09, D-10 — the AI status pill's texts and the mapping from a chat turn's outcome
 * to a pill state. Pure functions, so they are proven headlessly; MainTab paints them (it cannot be
 * built in a test), and plan 31-13 wires [BackendPill.healthOfTurn] to each chat turn's own result so
 * the first send refreshes the pill with no extra request.
 */
class BackendPillStateTest {
    @Test
    fun theIdleTextSaysNotCheckedWhenNothingWillCheckUnprompted() {
        assertEquals("Not checked · click to test", BackendPill.idleText(unpromptedAllowed = false))
        assertEquals(BackendPill.NOT_CHECKED, BackendPill.idleText(unpromptedAllowed = false))
    }

    @Test
    fun theIdleTextIsTheLegacyQuestionMarkWhenTheStartupCheckWillRun() {
        assertEquals("AI: ?", BackendPill.idleText(unpromptedAllowed = true))
        assertEquals(BackendPill.UNCHECKED_LEGACY, BackendPill.idleText(unpromptedAllowed = true))
    }

    @Test
    fun theDisabledTextNamesBurp() {
        assertEquals("AI disabled in Burp", BackendPill.AI_DISABLED)
    }

    @Test
    fun aPolicyRefusalIsRecognisedAsARefusal() {
        assertTrue(BackendPill.isRefusal(AiAccessRefusedException("x")))
    }

    @Test
    fun anOrdinaryErrorOrNoErrorIsNotARefusal() {
        assertFalse(BackendPill.isRefusal(IllegalStateException("x")), "a plain IllegalStateException is not the policy")
        assertFalse(BackendPill.isRefusal(null), "a successful turn is not a refusal")
    }

    @Test
    fun aSuccessfulTurnIsHealthy() {
        assertEquals(HealthCheckResult.Healthy, BackendPill.healthOfTurn(null))
    }

    @Test
    fun aFailedTurnIsUnavailableWithItsMessage() {
        assertEquals(HealthCheckResult.Unavailable("HTTP 500"), BackendPill.healthOfTurn(IllegalStateException("HTTP 500")))
    }

    @Test
    fun aFailedTurnWithNoMessageIsUnavailableWithAGenericMessage() {
        assertEquals(HealthCheckResult.Unavailable("Request failed"), BackendPill.healthOfTurn(RuntimeException()))
    }
}
