package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Phase 31 / D-15 — the one Output line written at load that states Burp's edition and what
 * `api.ai().isEnabled()` returned or threw. Phase 35's edition requirements are measured from it,
 * so a throw is reported, never swallowed. Reading it is local: no request is ever sent.
 */
class LoadDiagnosticsTest {
    private val apis = mutableListOf<MontoyaApi>()

    @AfterEach
    fun noProviderOrTargetTraffic() {
        apis.forEach { verify(it, never()).http() }
    }

    @Test
    fun reportsIsEnabledTrueWithTheEdition() {
        val api = apiWithEdition(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.ai().isEnabled()).thenReturn(true)

        assertEquals(
            "[Diagnostics] Burp PROFESSIONAL at load: api.ai().isEnabled() = true",
            burpAiLoadDiagnostics(api),
        )
    }

    @Test
    fun reportsIsEnabledFalseWithTheEdition() {
        val api = apiWithEdition(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.ai().isEnabled()).thenReturn(false)

        assertEquals(
            "[Diagnostics] Burp PROFESSIONAL at load: api.ai().isEnabled() = false",
            burpAiLoadDiagnostics(api),
        )
    }

    @Test
    fun reportsAThrowingIsEnabledByClassAndMessage() {
        val api = apiWithEdition(BurpSuiteEdition.COMMUNITY_EDITION)
        whenever(api.ai().isEnabled()).thenThrow(IllegalStateException("no AI"))

        assertEquals(
            "[Diagnostics] Burp COMMUNITY_EDITION at load: api.ai().isEnabled() threw IllegalStateException: no AI",
            burpAiLoadDiagnostics(api),
        )
    }

    @Test
    fun namesUnknownEditionWhenTheEditionLookupThrowsAndStillReportsIsEnabled() {
        val api = newApi()
        whenever(api.burpSuite()).thenThrow(UnsupportedOperationException("no version"))
        whenever(api.ai().isEnabled()).thenReturn(true)

        assertEquals(
            "[Diagnostics] Burp unknown edition at load: api.ai().isEnabled() = true",
            burpAiLoadDiagnostics(api),
        )
    }

    private fun apiWithEdition(edition: BurpSuiteEdition): MontoyaApi {
        val api = newApi()
        whenever(api.burpSuite().version().edition()).thenReturn(edition)
        return api
    }

    private fun newApi(): MontoyaApi = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also { apis += it }
}
