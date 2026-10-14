package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ManualPassiveScanStart
import com.six2dez.burp.aiagent.scanner.SuggestedQueueOutcome
import java.net.URI
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
 *
 * Phase 32 / D-04: also holds the result dialog of a hand-queued batch of suggested targets and the
 * "Confirm AI Active Scan" confirmation text shared with the context-menu AI Active Scan, so both show
 * the same sequence. Every message starts with extension wording or the policy's own text, never with a
 * URL or a parameter, and carries counts only (Swing treats a message starting with an HTML tag as HTML).
 */
internal object ManualScanDialogs {
    const val CONFIRM_ACTIVE_SCAN_TITLE = "Confirm AI Active Scan"

    val NO_SUGGESTED_SELECTION =
        ScanDialog("Select one or more suggested targets to queue.", "No selection", JOptionPane.INFORMATION_MESSAGE)

    private const val ACTIVE_SCAN_TITLE = "AI Active Scan"
    private const val ACTIVE_SCAN_STARTED_TITLE = "AI Active Scan Started"

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

    /** The "Confirm AI Active Scan" text: target, host and current queue counts, never a target's text. */
    fun confirmActiveScanMessage(
        targets: Int,
        hosts: Int,
        currentQueue: Int,
    ): String =
        "This will send active test payloads to $targets target(s) on $hosts host(s).\n" +
            "Current queue: $currentQueue\n\nDo you want to continue?"

    /** The number of distinct lower-cased hosts in [urls]; a URL with no parsable host counts as itself. */
    fun hostCount(urls: List<String>): Int = urls.mapTo(HashSet()) { url -> hostOf(url) ?: url }.size

    /** Phase 32 / D-04, D-08: the result dialog of a hand-queued batch of suggested targets. */
    fun suggested(
        outcome: SuggestedQueueOutcome,
        maxQueueSize: Int,
    ): ScanDialog =
        when (outcome) {
            is SuggestedQueueOutcome.Refused ->
                ScanDialog(outcome.reason, ACTIVE_SCAN_TITLE, JOptionPane.WARNING_MESSAGE)
            is SuggestedQueueOutcome.Queued ->
                if (outcome.queued.isEmpty()) {
                    ScanDialog(
                        "No suggested targets were queued. They are out of scope, not tested in the current scan mode, " +
                            "or the active scan queue is full (max $maxQueueSize).",
                        ACTIVE_SCAN_TITLE,
                        JOptionPane.WARNING_MESSAGE,
                    )
                } else {
                    ScanDialog(
                        "Queued ${outcome.queued.size} suggested target(s) for AI active testing." +
                            skippedPart(outcome.skipped) +
                            "\n\nThis will send test payloads to the server.\n" +
                            "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                        ACTIVE_SCAN_STARTED_TITLE,
                        JOptionPane.INFORMATION_MESSAGE,
                    )
                }
        }

    private fun skippedPart(skipped: Int): String =
        if (skipped == 0) {
            ""
        } else {
            "\n$skipped suggested target(s) were not queued (out of scope, not tested in the current scan mode, " +
                "or the queue is full)."
        }

    private fun hostOf(url: String): String? = runCatching { URI(url).host }.getOrNull()?.lowercase()
}
