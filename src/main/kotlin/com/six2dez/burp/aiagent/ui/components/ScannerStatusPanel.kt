package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.scanner.ActiveScannerStatus
import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus
import com.six2dez.burp.aiagent.ui.UiTheme
import com.six2dez.burp.aiagent.ui.passiveScanSummary
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel

/** Plain Swing rows also work when Burp's look and feel disables HTML labels. */
internal class ScannerStatusPanel : JPanel() {
    internal val passiveLabel = JLabel("Passive: waiting for Burp audit")
    internal val activeLabel = JLabel("Active: off")

    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        isOpaque = false
        for (label in listOf(passiveLabel, activeLabel)) {
            label.font = UiTheme.Typography.body
            label.foreground = UiTheme.Colors.onSurfaceVariant
            add(label)
        }
    }

    fun showStatus(
        passive: PassiveAiScannerStatus,
        active: ActiveScannerStatus,
    ) {
        passiveLabel.text = passiveScanSummary(passive)
        activeLabel.text = if (active.enabled) "Active: ${active.queueSize} queued | ${active.scansCompleted} done" else "Active: off"
        passiveLabel.toolTipText =
            "${passive.scanChecksReceived} audit callbacks; ${passive.outOfScopeSkipped} outside scope; ${passive.issuesFound} findings. " +
            "Automatic input requires Burp live passive audit. With In-scope only enabled, add the intended target in Target > Scope."
        activeLabel.toolTipText =
            "${active.vulnsConfirmed} confirmed. Auto-queue processes eligible passive findings; chat replies and site map entries are separate."
    }
}
