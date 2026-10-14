package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.Http
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever

/**
 * Phase 32 SC1 / BApp criterion 7 — the passive check never communicates with the target.
 *
 * Every case runs on the store classpath (no plug-in installed) with the AI passive scanner on and a
 * real active scanner switched on in FULL mode, so a regression that queued or sent anything from the
 * passive path would show up as an active-queue entry or a call on the mocked `Http`. Suggested targets
 * only land in the core list [PassiveAiScanner.suggestedTargets]. Each case uses its own host because
 * ScanKnowledgeBase is process-wide.
 */
class PassiveScanNoTargetTrafficTest {
    @Test
    fun anAiSqlInjectionFindingFillsTheCoreListAndSendsNothing() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val http = mockHttp(rig)
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            try {
                active.setEnabled(true)
                rig.scanner.setEnabled(true)
                val host = "sc1-ai.example"

                rig.scanner.handleParsedAiIssues(
                    listOf(AiIssueItem(title = "SQL Injection", severity = "High", detail = "d", confidence = 90)),
                    rig.csrfPost(host),
                    "LOW",
                )

                val suggested = rig.scanner.suggestedTargets.snapshot()
                assertTrue(suggested.isNotEmpty(), "the finding's injection points become suggestions")
                assertEquals(setOf(VulnClass.SQLI), suggested.map { it.target.vulnHint.vulnClass }.toSet())
                assertTrue(suggested.all { it.url.contains(host) }, "every suggestion is on $host: ${suggested.map { it.url }}")
                assertEquals(0, active.getStatus().queueSize, "nothing reaches the active queue")
                verifyNoInteractions(http)
                assertNull(rig.scanner.suggestedTargetSink, "the store classpath installs no plug-in sink")
                val calledOnSupervisor =
                    Mockito
                        .mockingDetails(rig.supervisor)
                        .invocations
                        .map { it.method.name }
                        .toSet()
                assertTrue(
                    ALLOWED_SUPERVISOR_CALLS.containsAll(calledOnSupervisor),
                    "only status, backend info and the policy pre-check reach the supervisor: $calledOnSupervisor",
                )
                val suggestLines = rig.output.filter { it.contains("suggest", ignoreCase = true) }
                assertEquals(emptyList<String>(), suggestLines, "adding suggestions writes no Output line (D-02)")
            } finally {
                active.shutdown()
            }
        }
    }

    @Test
    fun aLocalFindingIsRecordedButSuggestsAndSendsNothing() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val http = mockHttp(rig)
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            try {
                active.setEnabled(true)
                rig.scanner.setEnabled(true)
                val host = "sc1-local.example"

                rig.check.doCheck(rig.pageGet(host, smugglingIndicators = true))
                rig.drain()

                val finding = rig.scanner.getLastFindings(1).single()
                assertEquals("local", finding.source)
                val onHost =
                    rig.scanner.suggestedTargets
                        .snapshot()
                        .filter { it.url.contains(host) }
                assertEquals(emptyList<SuggestedTarget>(), onHost, "the local classes are passive-only (Pitfall 9)")
                assertEquals(0, active.getStatus().queueSize, "nothing reaches the active queue")
                verifyNoInteractions(http)
            } finally {
                active.shutdown()
            }
        }
    }

    @Test
    fun theRefusedGateAnalysesNothingSuggestsNothingAndSendsNothing() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val http = mockHttp(rig)
            whenever(rig.supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            try {
                active.setEnabled(true)
                rig.scanner.setEnabled(true)

                rig.check.doCheck(rig.pageGet("sc1-refused.example", smugglingIndicators = false))
                rig.drain()

                assertEquals(0, rig.analyzed(), "no AI analysis runs while the policy refuses")
                assertEquals(0, rig.scanner.suggestedTargets.count(), "no suggestion is added")
                assertEquals(0, active.getStatus().queueSize, "nothing reaches the active queue")
                verifyNoInteractions(http)
            } finally {
                active.shutdown()
            }
        }
    }

    @Test
    fun shutdownEmptiesTheList() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            rig.scanner.offerSuggestedTargets(rig.csrfPost("sc1-shutdown.example"), "SQL Injection", "High", "d", 90, rig.settings)
            assertTrue(rig.scanner.suggestedTargets.count() > 0, "precondition: the finding added suggestions")

            rig.scanner.shutdown()

            assertEquals(0, rig.scanner.suggestedTargets.count(), "nothing outlives the extension (D-06)")
        }
    }

    private fun mockHttp(rig: PassiveScanCheckRig): Http {
        val http = mock<Http>()
        whenever(rig.api.http()).thenReturn(http)
        return http
    }

    private fun sc1Settings(): AgentSettings =
        TestSettings.baselineSettings().copy(
            passiveAiEnabled = true,
            passiveAiScopeOnly = false,
            activeAiEnabled = true,
            activeAiScanMode = ScanMode.FULL,
        )

    private companion object {
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
        val ALLOWED_SUPERVISOR_CALLS = setOf("status", "getCurrentBackendInfo", "refusalForSavedBackend")
    }
}
