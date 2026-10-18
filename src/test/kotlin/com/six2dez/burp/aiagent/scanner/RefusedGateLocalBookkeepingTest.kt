package com.six2dez.burp.aiagent.scanner

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever

/**
 * Phase 31 gap closure WR-02 / D-02, D-07 — while the AI access policy refuses the saved backend, the
 * local (non-AI) findings the Burp Scanner passive check files keep their bookkeeping: one
 * `passive_ai_issue` audit record with source local, the issuesFound counter, the findings buffer and
 * the knowledge-base signal, all before doCheck returns, consolidated on repeats. The AI half still
 * skips every item: no executor submit, no backend start, no supervisor call besides the policy
 * pre-check and status, and one "Paused" Output line for the load. A scanner switched off records nothing.
 */
class RefusedGateLocalBookkeepingTest {
    @Test
    fun aLocalFindingKeepsItsBookkeepingWhileTheGateRefuses() {
        PassiveScanCheckRig().use { rig ->
            refuse(rig)
            rig.scanner.setEnabled(true)
            val rr = rig.csrfPost("refused-bookkeeping.example")
            val url = rr.request().url()

            val result = rig.check.doCheck(rr)

            // Recorded synchronously, before any drain.
            assertEquals(listOf("[AI Passive] CSRF"), result.auditIssues().map { it.name() })
            val event = rig.passiveIssueEvents().single()
            assertEquals("local", event["source"])
            assertEquals("Potential CSRF (Missing Token)", event["title"])
            assertEquals(1, rig.scanner.getStatus().issuesFound)
            val buffered = rig.scanner.getLastFindings(10).single()
            assertEquals("local" to true, buffered.source to buffered.issueCreated)
            assertEquals("local", ScanKnowledgeBase.getVulnSignals(url).single().source)
        }
    }

    @Test
    fun theRefusedGateStillSendsNothing() {
        PassiveScanCheckRig().use { rig ->
            refuse(rig)
            rig.scanner.setEnabled(true)

            rig.check.doCheck(rig.csrfPost("refused-sends-nothing.example"))

            assertEquals(0, rig.analyzed(), "the AI half analyzed nothing")
            assertEquals(emptyList<Any>(), rig.extensionAdds, "the extension filed nothing itself")
            val calledOnSupervisor =
                Mockito
                    .mockingDetails(rig.supervisor)
                    .invocations
                    .map { it.method.name }
                    .toSet()
            assertTrue(
                setOf("refusalForSavedBackend", "status").containsAll(calledOnSupervisor),
                "only the policy pre-check and status reach the supervisor: $calledOnSupervisor",
            )
            val paused = rig.output.filter { it.startsWith("[PassiveAiScanner] Paused: ") }
            assertEquals(1, paused.size, "one paused Output line for the load: $paused")
            assertTrue(paused.single().contains(REFUSAL), paused.single())
        }
    }

    @Test
    fun aRepeatUnderTheRefusedGateConsolidates() {
        PassiveScanCheckRig().use { rig ->
            refuse(rig)
            rig.scanner.setEnabled(true)
            val host = "refused-repeat.example"

            rig.fileLikeBurp(rig.check.doCheck(rig.csrfPost(host)))
            rig.check.doCheck(rig.csrfPost(host))

            assertEquals(1, rig.passiveIssueEvents().size, "a repeat writes no second audit event")
            assertEquals(1, rig.scanner.getStatus().issuesFound, "a repeat is not counted again")
            assertEquals(2, rig.scanner.getLastFindings(10).size, "every finding is buffered")
            assertEquals(
                1,
                rig.output.count { it.contains("Consolidated duplicate issue: [AI Passive] CSRF") },
                "one consolidation line for the repeat",
            )
        }
    }

    @Test
    fun aScannerSwitchedOffRecordsNothingWhileTheGateRefuses() {
        PassiveScanCheckRig().use { rig ->
            refuse(rig)

            val result = rig.check.doCheck(rig.csrfPost("refused-off.example"))

            assertEquals(emptyList<Any>(), result.auditIssues())
            assertEquals(emptyList<Any>(), rig.passiveIssueEvents())
            assertEquals(0, rig.scanner.getStatus().issuesFound)
            assertEquals(emptyList<Any>(), rig.scanner.getLastFindings(10))
        }
    }

    private fun refuse(rig: PassiveScanCheckRig) {
        whenever(rig.supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
    }

    private companion object {
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
    }
}
