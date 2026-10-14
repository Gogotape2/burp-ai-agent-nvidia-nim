package com.six2dez.burp.aiagent.spi

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget

/**
 * Phase 29 / D-02, BUILD-04 — the one seam between the passive scanner and anything that wants the
 * "suggested targets" a passive finding implies.
 *
 * The passive scanner maps a new finding's title to a vulnerability class, drops the passive-only
 * classes and the classes the current scan mode does not test, and builds one [ActiveScanTarget] per
 * injection point of the request. It adds that list to its core list (`PassiveAiScanner.suggestedTargets`,
 * Phase 32) and then offers the same list to its sink, if one is installed. The core never queues
 * target traffic from a passive finding.
 *
 * - Store build: no plug-in sink is installed. The suggested targets still reach the core list
 *   `PassiveAiScanner.suggestedTargets`, where the user sees them and queues them by hand after a
 *   confirmation; the passive scan itself sends nothing to the target.
 * - Full build: the opt-in auto-queue plug-in installs a sink that is offered the same targets after
 *   the core list has them. It forwards them to the AI Active Scanner only when its own toggle and the
 *   active scanner are both on.
 *
 * [offer] runs on the passive scanner's worker thread or on one of Burp's passive-scan threads
 * (through `recordScanCheckFindings`), never on the EDT, and only with a non-empty list. It must not
 * block: Burp's passive-scan threads wait for it.
 */
interface SuggestedTargetSink {
    fun offer(
        targets: List<ActiveScanTarget>,
        settings: AgentSettings,
    )
}
