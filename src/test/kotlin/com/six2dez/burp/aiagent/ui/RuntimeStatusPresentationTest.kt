package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RuntimeStatusPresentationTest {
    @Test
    fun nimWithoutWorkerDoesNotLookDisconnected() {
        assertEquals("Worker: On demand | nvidia-nim", workerStatusText("Idle", null, "nvidia-nim"))
        assertEquals("Worker: Running | codex-cli", workerStatusText("Running", "codex-cli", "nvidia-nim"))
    }

    @Test
    fun passiveSummaryDistinguishesScopeBudgetAndMissingAudit() {
        val base = PassiveAiScannerStatus(true, 0, 0, 0, 0)
        assertEquals("Passive: waiting for Burp audit", passiveScanSummary(base))
        assertEquals("Passive: outside scope (8)", passiveScanSummary(base.copy(scanChecksReceived = 8, outOfScopeSkipped = 8, lastCheckOutsideScope = true)))
        assertEquals("Passive: paused (token cap)", passiveScanSummary(base.copy(budgetPaused = true)))
        assertEquals("Passive: 2 queued | 0 done", passiveScanSummary(base.copy(queueSize = 2)))
        assertEquals("Passive: off", passiveScanSummary(base.copy(enabled = false)))
    }
}
