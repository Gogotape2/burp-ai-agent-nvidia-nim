package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ActiveScannerStatus
import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.panels.ActiveScanConfigPanel
import com.six2dez.burp.aiagent.ui.panels.ActiveScanQueuePanel
import com.six2dez.burp.aiagent.ui.panels.PassiveScanConfigPanel
import com.six2dez.burp.aiagent.ui.panels.suggestedCounterText
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

internal fun SettingsPanel.passiveAiScannerSection(): JPanel =
    PassiveScanConfigPanel(
        passiveAiEnabled = passiveAiEnabled,
        passiveAiScopeOnly = passiveAiScopeOnly,
        passiveAiRateSpinner = passiveAiRateSpinner,
        passiveAiMaxSizeSpinner = passiveAiMaxSizeSpinner,
        passiveAiMinSeverityCombo = passiveAiMinSeverityCombo,
        passiveAiEndpointDedupSpinner = passiveAiEndpointDedupSpinner,
        passiveAiFingerprintDedupSpinner = passiveAiFingerprintDedupSpinner,
        passiveAiPromptCacheTtlSpinner = passiveAiPromptCacheTtlSpinner,
        passiveAiEndpointCacheEntriesSpinner = passiveAiEndpointCacheEntriesSpinner,
        passiveAiFingerprintCacheEntriesSpinner = passiveAiFingerprintCacheEntriesSpinner,
        passiveAiPromptCacheEntriesSpinner = passiveAiPromptCacheEntriesSpinner,
        passiveAiRequestBodyMaxCharsSpinner = passiveAiRequestBodyMaxCharsSpinner,
        passiveAiResponseBodyMaxCharsSpinner = passiveAiResponseBodyMaxCharsSpinner,
        passiveAiHeaderMaxCountSpinner = passiveAiHeaderMaxCountSpinner,
        passiveAiParamMaxCountSpinner = passiveAiParamMaxCountSpinner,
        passiveAiExcludedExtensionsField = passiveAiExcludedExtensionsField,
        passiveAiBatchSizeSpinner = passiveAiBatchSizeSpinner,
        passiveAiPersistentCacheEnabled = passiveAiPersistentCacheEnabled,
        passiveAiPersistentCacheTtlSpinner = passiveAiPersistentCacheTtlSpinner,
        passiveAiPersistentCacheMaxMbSpinner = passiveAiPersistentCacheMaxMbSpinner,
        contextRequestBodyMaxCharsSpinner = contextRequestBodyMaxCharsSpinner,
        contextResponseBodyMaxCharsSpinner = contextResponseBodyMaxCharsSpinner,
        contextCompactJson = contextCompactJson,
        passiveAiStatusLabel = passiveAiStatusLabel,
        passiveAiViewFindings = passiveAiViewFindings,
        scannerTriageButton = scannerTriageButton,
        passiveAiResetStats = passiveAiResetStats,
        tokenBudgetWarnField = tokenBudgetWarnField,
        tokenBudgetHardCapField = tokenBudgetHardCapField,
    ).build()

/** Phase 31 / D-02: the scanner panel segment shown while a scanner is ON and the AI gate refuses it. */
const val AI_GATE_PAUSED_TEXT = "Paused: Use AI is off"

/**
 * The passive scanner status line, pure so it can be tested without Swing. [lastTime] is the already
 * formatted last-analysis time ("Never" when nothing ran). While the scanner is ON and
 * [PassiveAiScannerStatus.aiGatePaused] is set, [AI_GATE_PAUSED_TEXT] follows the ON marker; the rest
 * of the line is unchanged.
 */
internal fun passiveAiStatusText(
    status: PassiveAiScannerStatus,
    manualInProgress: Boolean,
    manualCompleted: Int,
    manualTotal: Int,
    lastTime: String,
): String =
    buildString {
        if (manualInProgress) {
            append("Manual scan: $manualCompleted/$manualTotal | ")
        }
        if (status.enabled) {
            append("Passive: ON | ")
            if (status.aiGatePaused) {
                append("$AI_GATE_PAUSED_TEXT | ")
            }
            append("Analyzed: ${status.requestsAnalyzed} | Issues: ${status.issuesFound} | Last: $lastTime")
        } else {
            append("Passive: OFF")
            if (!manualInProgress) {
                append(" | Total issues: ${status.issuesFound}")
            }
        }
    }

internal fun SettingsPanel.refreshPassiveAiStatus() {
    val status = passiveAiScanner.getStatus()
    val (manualInProgress, manualCompleted, manualTotal) = passiveAiScanner.getManualScanProgress()
    val lastTime =
        if (status.lastAnalysisTime > 0) {
            val formatter =
                DateTimeFormatter
                    .ofPattern("HH:mm:ss")
                    .withZone(ZoneId.systemDefault())
            formatter.format(Instant.ofEpochMilli(status.lastAnalysisTime))
        } else {
            "Never"
        }
    passiveAiStatusLabel.text = passiveAiStatusText(status, manualInProgress, manualCompleted, manualTotal, lastTime)
}

internal fun SettingsPanel.applyPassiveAiSettings() {
    passiveAiScanner.rateLimitSeconds = (passiveAiRateSpinner.value as? Int) ?: 5
    passiveAiScanner.scopeOnly = passiveAiScopeOnly.isSelected
    passiveAiScanner.maxSizeKb = (passiveAiMaxSizeSpinner.value as? Int) ?: 96
    passiveAiScanner.endpointDedupMinutes = (passiveAiEndpointDedupSpinner.value as? Int) ?: 30
    passiveAiScanner.responseFingerprintDedupMinutes =
        (passiveAiFingerprintDedupSpinner.value as? Int) ?: 30
    passiveAiScanner.promptCacheTtlMinutes = (passiveAiPromptCacheTtlSpinner.value as? Int) ?: 30
    passiveAiScanner.endpointCacheEntries = (passiveAiEndpointCacheEntriesSpinner.value as? Int) ?: 5_000
    passiveAiScanner.responseFingerprintCacheEntries =
        (passiveAiFingerprintCacheEntriesSpinner.value as? Int) ?: 5_000
    passiveAiScanner.promptCacheEntries = (passiveAiPromptCacheEntriesSpinner.value as? Int) ?: 500
    passiveAiScanner.requestBodyPromptMaxChars =
        (passiveAiRequestBodyMaxCharsSpinner.value as? Int) ?: 2_000
    passiveAiScanner.responseBodyPromptMaxChars =
        (passiveAiResponseBodyMaxCharsSpinner.value as? Int) ?: 4_000
    passiveAiScanner.headerMaxCount = (passiveAiHeaderMaxCountSpinner.value as? Int) ?: 40
    passiveAiScanner.paramMaxCount = (passiveAiParamMaxCountSpinner.value as? Int) ?: 15
    // Propagate excluded extensions, batch size, and persistent cache via optimization settings
    passiveAiScanner.applyOptimizationSettings(currentSettings())
    passiveAiScanner.setEnabled(passiveAiEnabled.isSelected)
    refreshPassiveAiStatus()
}

internal fun SettingsPanel.showPassiveAiFindingsDialog() {
    val findings = passiveAiScanner.getLastFindings(20)
    if (findings.isEmpty()) {
        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            "No findings yet. Enable the scanner and browse the target to generate findings.",
            "AI Passive Scanner Findings",
            JOptionPane.INFORMATION_MESSAGE,
        )
        return
    }

    val sb = StringBuilder()
    sb.append("Recent AI Passive Scanner Findings:\n\n")
    findings.reversed().forEach { finding ->
        val time =
            java.time.Instant
                .ofEpochMilli(finding.timestamp)
                .atZone(java.time.ZoneId.systemDefault())
                .format(
                    java.time.format.DateTimeFormatter
                        .ofPattern("HH:mm:ss"),
                )
        sb.append("[$time] ${finding.severity} - ${finding.title}\n")
        sb.append("  URL: ${finding.url}\n")
        sb.append("  Detail: ${finding.detail.take(100)}${if (finding.detail.length > 100) "..." else ""}\n")
        sb.append("  Confidence: ${finding.confidence}% | Source: ${finding.source}")
        if (!finding.issueCreated) sb.append(" | Not created as issue")
        sb.append("\n\n")
    }

    val textArea = JTextArea(sb.toString())
    textArea.isEditable = false
    textArea.font = DesignTokens.Typography.mono
    textArea.rows = 20
    textArea.columns = 60

    JOptionPane.showMessageDialog(
        dialogParentComponent(),
        JScrollPane(textArea),
        "AI Passive Scanner Findings (${findings.size} recent)",
        JOptionPane.PLAIN_MESSAGE,
    )
}

internal fun SettingsPanel.activeAiScannerSection(): JPanel =
    ActiveScanConfigPanel(
        activeAiEnabled = activeAiEnabled,
        activeAiScopeOnly = activeAiScopeOnly,
        activeAiMaxConcurrentSpinner = activeAiMaxConcurrentSpinner,
        activeAiMaxPayloadsSpinner = activeAiMaxPayloadsSpinner,
        activeAiTimeoutSpinner = activeAiTimeoutSpinner,
        activeAiDelaySpinner = activeAiDelaySpinner,
        activeAiRiskLevelCombo = activeAiRiskLevelCombo,
        activeAiScanModeCombo = activeAiScanModeCombo,
        activeAiUseCollaborator = activeAiUseCollaborator,
        activeAiAdaptivePayloads = activeAiAdaptivePayloads,
        activeAiRiskDescription = activeAiRiskDescription,
        activeAiStatusLabel = activeAiStatusLabel,
        activeAiViewFindings = activeAiViewFindings,
        activeAiViewQueue = activeAiViewQueue,
        activeAiClearQueue = activeAiClearQueue,
        activeAiResetStats = activeAiResetStats,
        contributions = contributedComponents(SettingsSlot.ACTIVE_SCANNER_TAB),
    ).build()

internal fun SettingsPanel.updateActiveRiskDescription() {
    val level = (activeAiRiskLevelCombo.selectedItem as? String ?: "SAFE").uppercase()
    activeAiRiskDescription.text =
        when (level) {
            "SAFE" -> "Read-only payloads. No data modified. Safe for bug bounty."
            "MODERATE" -> "May read sensitive data. Could trigger IDS/WAF."
            "DANGEROUS" -> "May modify or delete data. Only for authorized pentests."
            else -> "Risk level not recognized."
        }
}

/**
 * The active scanner status line, pure so it can be tested without Swing. While the scanner is ON and
 * [ActiveScannerStatus.aiGatePaused] is set, [AI_GATE_PAUSED_TEXT] follows the ON marker; the rest of
 * the line is unchanged.
 *
 * Phase 32 / D-02, D-07: when [suggested] > 0, both the ON and the OFF forms end with " | " plus
 * [suggestedCounterText] ("Suggested: N", plus " (cap reached)" once [suggestedCapReached]), the same
 * wording as the queue dialog's Suggested section. The count is a local read of the in-memory list;
 * nothing is sent. With [suggested] == 0 the line is exactly the pre-phase text.
 *
 * Phase 33 / D-04: while an OFF request is still stopping the scanner ([ActiveScannerStatus.stopping]),
 * the line starts with "Active: Stopping…" instead of ON or OFF, so the label never says OFF while
 * workers may still run. It keeps the OFF form's confirmed count and the suggested suffix. Every other
 * line is unchanged.
 */
internal fun activeAiStatusText(
    status: ActiveScannerStatus,
    suggested: Int = 0,
    suggestedCapReached: Boolean = false,
): String =
    buildString {
        if (status.stopping) {
            append("Active: Stopping…")
            if (status.vulnsConfirmed > 0) {
                append(" | Confirmed: ${status.vulnsConfirmed}")
            }
        } else if (status.enabled) {
            append("Active: ON")
            if (status.aiGatePaused) {
                append(" | $AI_GATE_PAUSED_TEXT")
            }
            if (status.scanning) {
                append(" | Scanning")
                status.currentTarget?.let { target ->
                    append(" (${target.take(40)}...)")
                }
            }
            append(" | Queue: ${status.queueSize}")
            append(" | Scans: ${status.scansCompleted}")
            append(" | Confirmed: ${status.vulnsConfirmed}")
        } else {
            append("Active: OFF")
            if (status.vulnsConfirmed > 0) {
                append(" | Confirmed: ${status.vulnsConfirmed}")
            }
        }
        if (suggested > 0) {
            append(" | ")
            append(suggestedCounterText(suggested, suggestedCapReached))
        }
    }

internal fun SettingsPanel.refreshActiveAiStatus() {
    activeAiStatusLabel.text =
        activeAiStatusText(
            activeAiScanner.getStatus(),
            passiveAiScanner.suggestedTargets.count(),
            passiveAiScanner.suggestedTargets.capReached(),
        )
}

/**
 * Phase 33 / D-01, D-03, EDT-01 — hot-applies the Settings tab's active scanner controls (everything
 * except the on/off toggle). Plain setters only: the scanner is never started, stopped or restarted
 * here, new values apply to the next target, `maxConcurrent` resizes the live worker pool, and the
 * shared baselines, pending Collaborator confirmations and the Collaborator client are kept.
 * Safe on the EDT.
 */
internal fun SettingsPanel.applyActiveAiTunables() {
    updateActiveRiskDescription()
    activeAiScanner.maxConcurrent = (activeAiMaxConcurrentSpinner.value as? Int) ?: 3
    activeAiScanner.maxPayloadsPerPoint = (activeAiMaxPayloadsSpinner.value as? Int) ?: 10
    activeAiScanner.timeoutSeconds = (activeAiTimeoutSpinner.value as? Int) ?: 30
    activeAiScanner.requestDelayMs = ((activeAiDelaySpinner.value as? Int) ?: 100).toLong()
    activeAiScanner.maxRiskLevel = PayloadRisk.fromString(activeAiRiskLevelCombo.selectedItem as? String)
    activeAiScanner.scopeOnly = activeAiScopeOnly.isSelected
    activeAiScanner.scanMode = ScanMode.fromString(activeAiScanModeCombo.selectedItem as? String)
    activeAiScanner.useCollaborator = activeAiUseCollaborator.isSelected
}

/**
 * Phase 33 / D-01, D-04, EDT-01 — the only Settings path that starts or stops the active scanner (the
 * Settings toggle, and the header toggle through [setActiveAiEnabled]).
 *
 * Asks the scanner only when the toggle differs from its current intent, through the non-blocking
 * `requestEnabled`: the start or stop runs on the scanner's lifecycle thread, so this returns at once
 * on the EDT, and a second click during a stop is serialized behind it (the latest click wins). The
 * status is refreshed at once, so "Active: Stopping…" shows while an OFF runs, and again on the EDT
 * when the transition settles.
 */
internal fun SettingsPanel.applyActiveAiEnabled() {
    if (activeAiEnabled.isSelected != activeAiScanner.isEnabled()) {
        activeAiScanner.requestEnabled(activeAiEnabled.isSelected) {
            SwingUtilities.invokeLater { refreshActiveAiStatus() }
        }
    }
    refreshActiveAiStatus()
}

internal fun SettingsPanel.showActiveAiFindingsDialog() {
    val findings = activeAiScanner.getRecentConfirmations(20)
    if (findings.isEmpty()) {
        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            "No active confirmations yet. Run active scans to generate findings.",
            "AI Active Scanner Findings",
            JOptionPane.INFORMATION_MESSAGE,
        )
        return
    }

    val sb = StringBuilder()
    sb.append("Recent AI Active Scanner Confirmations:\n\n")
    findings.reversed().forEach { finding ->
        val time =
            java.time.Instant
                .ofEpochMilli(finding.timestamp)
                .atZone(java.time.ZoneId.systemDefault())
                .format(
                    java.time.format.DateTimeFormatter
                        .ofPattern("HH:mm:ss"),
                )
        sb.append("[$time] ${finding.severity} - ${finding.title}\n")
        sb.append("  URL: ${finding.url}\n")
        sb.append("  Confidence: ${finding.confidence}%\n")
        sb.append("  Detail: ${finding.detail.take(120)}${if (finding.detail.length > 120) "..." else ""}\n\n")
    }

    val textArea = JTextArea(sb.toString())
    textArea.isEditable = false
    textArea.font = DesignTokens.Typography.mono
    textArea.rows = 20
    textArea.columns = 60

    JOptionPane.showMessageDialog(
        dialogParentComponent(),
        JScrollPane(textArea),
        "AI Active Scanner Findings (${findings.size} recent)",
        JOptionPane.PLAIN_MESSAGE,
    )
}

internal fun SettingsPanel.showActiveScanQueueDialog() {
    ActiveScanQueuePanel.showDialog(dialogParentComponent(), activeAiScanner, passiveAiScanner.suggestedTargets)
}

internal fun SettingsPanel.showScannerTriageDialog() {
    val passiveFindings = passiveAiScanner.getLastFindings(50)
    val activeFindings = activeAiScanner.getRecentConfirmations(50)
    if (passiveFindings.isEmpty() && activeFindings.isEmpty()) {
        JOptionPane.showMessageDialog(
            dialogParentComponent(),
            "No findings yet. Run passive or active scans to populate triage.",
            "Scanner Triage",
            JOptionPane.INFORMATION_MESSAGE,
        )
        return
    }

    data class TriageEntry(
        val title: String,
        val url: String,
        val severity: String,
        val confidence: Int,
        val source: String,
        val count: Int,
        val lastSeen: Long,
        val detail: String,
    )

    val entries = mutableListOf<TriageEntry>()

    val passiveGrouped = passiveFindings.groupBy { "${it.title}::${it.url}" }
    passiveGrouped.values.forEach { group ->
        val first = group.first()
        entries.add(
            TriageEntry(
                title = first.title,
                url = first.url,
                severity = first.severity,
                confidence = group.maxOf { it.confidence },
                source = "passive",
                count = group.size,
                lastSeen = group.maxOf { it.timestamp },
                detail = first.detail,
            ),
        )
    }

    val activeGrouped = activeFindings.groupBy { "${it.title}::${it.url}" }
    activeGrouped.values.forEach { group ->
        val first = group.first()
        entries.add(
            TriageEntry(
                title = first.title,
                url = first.url,
                severity = first.severity,
                confidence = group.maxOf { it.confidence },
                source = "active",
                count = group.size,
                lastSeen = group.maxOf { it.timestamp },
                detail = first.detail,
            ),
        )
    }

    val sorted =
        entries.sortedWith(
            compareByDescending<TriageEntry> { severityRank(it.severity) }
                .thenByDescending { it.confidence }
                .thenByDescending { it.lastSeen },
        )

    val sb = StringBuilder()
    sb.append("Scanner Triage Summary:\n\n")
    sorted.forEach { entry ->
        val time =
            java.time.Instant
                .ofEpochMilli(entry.lastSeen)
                .atZone(java.time.ZoneId.systemDefault())
                .format(
                    java.time.format.DateTimeFormatter
                        .ofPattern("HH:mm:ss"),
                )
        sb.append("[${entry.severity}] ${entry.title} (${entry.source}) x${entry.count}\n")
        sb.append("  URL: ${entry.url}\n")
        sb.append("  Confidence: ${entry.confidence}% | Last seen: $time\n")
        sb.append("  Detail: ${entry.detail.take(120)}${if (entry.detail.length > 120) "..." else ""}\n\n")
    }

    val textArea = JTextArea(sb.toString())
    textArea.isEditable = false
    textArea.font = DesignTokens.Typography.mono
    textArea.rows = 24
    textArea.columns = 70

    JOptionPane.showMessageDialog(
        dialogParentComponent(),
        JScrollPane(textArea),
        "Scanner Triage (${sorted.size} grouped findings)",
        JOptionPane.PLAIN_MESSAGE,
    )
}

internal fun SettingsPanel.severityRank(severity: String): Int =
    when (severity.uppercase()) {
        "CRITICAL" -> 4
        "HIGH" -> 3
        "MEDIUM" -> 2
        "LOW" -> 1
        else -> 0
    }
