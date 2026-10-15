package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import java.awt.Component
import javax.swing.JOptionPane

/**
 * Phase 32 / D-04 — the Swing prompts of an AI active scan, shared by the context-menu "AI Active Scan"
 * and the suggested-targets queue so the user sees one consistent sequence: the enable-scanner prompt,
 * then the confirmation built by [ManualScanDialogs.confirmActiveScanMessage]. EDT only.
 */
internal object ActiveScanPrompts {
    /**
     * Makes sure [activeAiScanner] is on: warns when it is not available, and asks to switch it on when
     * it is off. Returns true when the scanner is on afterwards.
     */
    @Suppress("ReturnCount") // body moved from UiActions.ensureActiveScannerEnabled (baseline-keyed on its signature); ADR-17 forbids a new entry
    fun ensureActiveScannerEnabled(
        parent: Component?,
        activeAiScanner: ActiveAiScanner?,
    ): Boolean {
        if (activeAiScanner == null) {
            JOptionPane.showMessageDialog(parent, "Active Scanner not available.", "Custom AI Agent", JOptionPane.WARNING_MESSAGE)
            return false
        }
        if (!activeAiScanner.isEnabled()) {
            val enable =
                JOptionPane.showConfirmDialog(
                    parent,
                    "Active Scanner is disabled. Enable it now?",
                    "Custom AI Agent",
                    JOptionPane.YES_NO_OPTION,
                )
            if (enable == JOptionPane.YES_OPTION) {
                // Phase 33 EDT-01: requestEnabled sets the enabled intent at once, so the queue call that
                // follows accepts targets, while processing starts on the scanner's lifecycle thread.
                activeAiScanner.requestEnabled(true)
            } else {
                return false
            }
        }
        return true
    }

    /** Shows the active scan confirmation with [message]; true only for Yes. */
    fun confirmActiveScan(
        parent: Component?,
        message: String,
    ): Boolean =
        JOptionPane.showConfirmDialog(
            parent,
            message,
            ManualScanDialogs.CONFIRM_ACTIVE_SCAN_TITLE,
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
        ) == JOptionPane.YES_OPTION
}

/** Phase 32 / D-04 — the Swing [SuggestedQueuePrompts] of the suggested-targets queue. EDT only. */
internal class SwingSuggestedQueuePrompts(
    private val parent: Component?,
    private val scanner: ActiveAiScanner,
) : SuggestedQueuePrompts {
    override fun show(dialog: ScanDialog) {
        JOptionPane.showMessageDialog(parent, dialog.message, dialog.title, dialog.messageType)
    }

    override fun ensureScannerEnabled(): Boolean = ActiveScanPrompts.ensureActiveScannerEnabled(parent, scanner)

    override fun confirm(message: String): Boolean = ActiveScanPrompts.confirmActiveScan(parent, message)
}
