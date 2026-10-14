package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ManualPassiveScanStart
import javax.swing.JOptionPane

/** The message dialog a manual scan menu action shows: text, title and a JOptionPane message type. */
internal data class ScanDialog(
    val message: String,
    val title: String,
    val messageType: Int,
)

/**
 * Phase 31 gap closure WR-04 / D-01: maps the outcome of a manual scan request to the dialog the user
 * sees. A refusal shows the AI access policy's own text in a warning, where the user acted; a queued
 * scan keeps the success dialog unchanged. Pure and headless-testable: no Swing component is built here.
 */
internal object ManualScanDialogs {
    fun passive(start: ManualPassiveScanStart): ScanDialog =
        when (start) {
            is ManualPassiveScanStart.Refused ->
                ScanDialog(start.reason, "AI Passive Scan", JOptionPane.WARNING_MESSAGE)
            is ManualPassiveScanStart.Queued ->
                ScanDialog(
                    "Queued ${start.count} request(s) for AI passive analysis.\n\n" +
                        "Findings will appear in Target → Issues with [AI Passive] prefix.",
                    "AI Passive Scan Started",
                    JOptionPane.INFORMATION_MESSAGE,
                )
        }
}
