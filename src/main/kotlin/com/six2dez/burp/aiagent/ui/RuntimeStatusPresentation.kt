package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus

internal fun workerStatusText(
    state: String,
    workerBackendId: String?,
    selectedBackendId: String,
): String {
    val label = if (state == "Idle" && selectedBackendId == "nvidia-nim") "On demand" else state
    return "Worker: $label | ${workerBackendId ?: selectedBackendId}"
}

internal fun passiveScanSummary(status: PassiveAiScannerStatus): String =
    when {
        !status.enabled -> "Passive: off"
        status.budgetPaused -> "Passive: paused (token cap)"
        status.queueSize > 0 || status.analyzing -> "Passive: ${status.queueSize} queued | ${status.requestsAnalyzed} done"
        status.lastCheckOutsideScope -> "Passive: outside scope (${status.outOfScopeSkipped})"
        status.scanChecksReceived == 0 && status.requestsAnalyzed == 0 -> "Passive: waiting for Burp audit"
        else -> "Passive: ${status.requestsAnalyzed} done | ${status.issuesFound} findings"
    }
