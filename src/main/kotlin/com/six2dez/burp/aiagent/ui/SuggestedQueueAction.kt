package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.SuggestedQueueOutcome
import com.six2dez.burp.aiagent.scanner.SuggestedTarget
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList

/**
 * Phase 32 / D-04 — the prompts the queue-suggested flow shows. The Swing adapter is
 * [SwingSuggestedQueuePrompts]; tests pass a recording fake, so no dialog is shown headless.
 */
internal interface SuggestedQueuePrompts {
    /** Shows a message dialog. */
    fun show(dialog: ScanDialog)

    /** Makes sure the active scanner is on, asking the user to switch it on; false when it stays off. */
    fun ensureScannerEnabled(): Boolean

    /** Asks the [ManualScanDialogs.CONFIRM_ACTIVE_SCAN_TITLE] question with [message]; true only for Yes. */
    fun confirm(message: String): Boolean
}

/**
 * Phase 32 / D-04, D-05, D-08 — queues suggested targets by hand, through the same sequence as the
 * context-menu "AI Active Scan".
 *
 * In order: the AI access policy is asked first and a refusal is shown verbatim with nothing else
 * asked (research A3: a refused action never switches the scanner on); then the scanner is switched
 * on if needed; then the [ManualScanDialogs.CONFIRM_ACTIVE_SCAN_TITLE] confirmation with target and
 * host counts (D-05: the explicit user action, nothing is queued without a Yes); then
 * [ActiveAiScanner.queueSuggested]. Only
 * the targets the scanner really queued leave [list] (D-08); filtered, out-of-scope or overflow
 * targets stay. A result dialog closes the flow. No Swing here: the prompts sit behind [prompts].
 */
internal class SuggestedQueueAction(
    private val list: SuggestedTargetList,
    private val scanner: ActiveAiScanner,
    private val prompts: SuggestedQueuePrompts,
) {
    /**
     * Runs the flow for [entries] and returns what the scanner did, or null when nothing was attempted:
     * an empty selection, the scanner left off, or No to the confirmation.
     */
    fun queue(entries: List<SuggestedTarget>): SuggestedQueueOutcome? {
        if (entries.isEmpty()) {
            prompts.show(ManualScanDialogs.NO_SUGGESTED_SELECTION)
            return null
        }
        // Evaluated before ensureScannerEnabled, so a refusal never offers to switch the scanner on.
        val refusal = scanner.suggestedQueueRefusal()
        val outcome =
            when {
                refusal != null -> SuggestedQueueOutcome.Refused(refusal)
                !prompts.ensureScannerEnabled() -> null
                !prompts.confirm(confirmationFor(entries)) -> null
                else -> scanner.queueSuggested(entries.map { it.target })
            }
        if (outcome is SuggestedQueueOutcome.Queued) list.removeAll(outcome.queued)
        if (outcome != null) prompts.show(ManualScanDialogs.suggested(outcome, scanner.maxQueueSize))
        return outcome
    }

    private fun confirmationFor(entries: List<SuggestedTarget>): String =
        ManualScanDialogs.confirmActiveScanMessage(
            entries.size,
            ManualScanDialogs.hostCount(entries.map { it.url }),
            scanner.getStatus().queueSize,
        )
}
