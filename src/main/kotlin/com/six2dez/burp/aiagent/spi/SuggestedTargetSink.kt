package com.six2dez.burp.aiagent.spi

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget

/**
 * Phase 29 / D-02, BUILD-04 — the one seam between the passive scanner and anything that wants the
 * "suggested targets" a passive finding implies.
 *
 * The passive scanner maps a new finding's title to a vulnerability class, drops the passive-only
 * classes and the classes the current scan mode does not test, and builds one [ActiveScanTarget] per
 * injection point of the request. It then offers that list to its sink, if one is installed, and does
 * nothing else with it. The core never queues target traffic from a passive finding.
 *
 * - Store build: no sink is installed, so the list is not even built and the passive scan sends
 *   nothing to the target.
 * - Full build: the opt-in auto-queue plug-in installs a sink that forwards the targets to the AI
 *   Active Scanner only when its own toggle and the active scanner are both on.
 *
 * [offer] runs on the passive scanner's worker thread, never on the EDT, and only with a non-empty
 * list. It must not block for long: the passive scanner analyses one request at a time.
 */
interface SuggestedTargetSink {
    fun offer(
        targets: List<ActiveScanTarget>,
        settings: AgentSettings,
    )
}
