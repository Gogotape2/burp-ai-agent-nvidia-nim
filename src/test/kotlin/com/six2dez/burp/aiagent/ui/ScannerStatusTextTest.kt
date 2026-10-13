package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ActiveScannerStatus
import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 31 / D-02 — the scanner panel says "Paused: Use AI is off" while a scanner is ON and the AI
 * access policy refuses its backend, and otherwise renders exactly the pre-phase status line.
 */
class ScannerStatusTextTest {
    @Test
    fun pausedTextIsTheExactUserFacingWording() {
        assertEquals("Paused: Use AI is off", AI_GATE_PAUSED_TEXT)
    }

    @Test
    fun pausedPassiveScannerShowsThePausedSegmentRightAfterTheOnMarker() {
        val text = passiveAiStatusText(passive(enabled = true, paused = true), false, 0, 0, "Never")

        assertTrue(text.startsWith("Passive: ON | $AI_GATE_PAUSED_TEXT | "), text)
        assertEquals("Passive: ON | Paused: Use AI is off | Analyzed: 7 | Issues: 2 | Last: Never", text)
    }

    @Test
    fun unpausedPassiveScannerKeepsTodaysFormat() {
        assertEquals(
            "Passive: ON | Analyzed: 7 | Issues: 2 | Last: 12:34:56",
            passiveAiStatusText(passive(enabled = true, paused = false), false, 0, 0, "12:34:56"),
        )
        assertEquals(
            "Manual scan: 1/3 | Passive: ON | Analyzed: 7 | Issues: 2 | Last: Never",
            passiveAiStatusText(passive(enabled = true, paused = false), true, 1, 3, "Never"),
        )
        assertEquals("Passive: OFF | Total issues: 2", passiveAiStatusText(passive(enabled = false, paused = false), false, 0, 0, "Never"))
        assertEquals("Manual scan: 1/3 | Passive: OFF", passiveAiStatusText(passive(enabled = false, paused = false), true, 1, 3, "Never"))
    }

    @Test
    fun anOffPassiveScannerNeverShowsThePausedText() {
        val text = passiveAiStatusText(passive(enabled = false, paused = true), false, 0, 0, "Never")

        assertFalse(text.contains(AI_GATE_PAUSED_TEXT), text)
        assertEquals("Passive: OFF | Total issues: 2", text)
    }

    @Test
    fun pausedActiveScannerShowsThePausedSegmentRightAfterTheOnMarker() {
        assertEquals(
            "Active: ON | Paused: Use AI is off | Queue: 0 | Scans: 4 | Confirmed: 1",
            activeAiStatusText(active(enabled = true, paused = true)),
        )
    }

    @Test
    fun unpausedActiveScannerKeepsTodaysFormat() {
        assertEquals("Active: ON | Queue: 0 | Scans: 4 | Confirmed: 1", activeAiStatusText(active(enabled = true, paused = false)))
        assertEquals(
            "Active: ON | Scanning (https://target.example/a...) | Queue: 0 | Scans: 4 | Confirmed: 1",
            activeAiStatusText(active(enabled = true, paused = false).copy(scanning = true, currentTarget = "https://target.example/a")),
        )
        assertEquals("Active: OFF | Confirmed: 1", activeAiStatusText(active(enabled = false, paused = false)))
    }

    @Test
    fun anOffActiveScannerNeverShowsThePausedText() {
        assertEquals("Active: OFF | Confirmed: 1", activeAiStatusText(active(enabled = false, paused = true)))
    }

    private fun active(
        enabled: Boolean,
        paused: Boolean,
    ) = ActiveScannerStatus(
        enabled = enabled,
        queueSize = 0,
        scanning = false,
        scansCompleted = 4,
        vulnsConfirmed = 1,
        currentTarget = null,
        aiGatePaused = paused,
    )

    private fun passive(
        enabled: Boolean,
        paused: Boolean,
    ) = PassiveAiScannerStatus(
        enabled = enabled,
        requestsAnalyzed = 7,
        issuesFound = 2,
        lastAnalysisTime = 0L,
        queueSize = 0,
        aiGatePaused = paused,
    )
}
