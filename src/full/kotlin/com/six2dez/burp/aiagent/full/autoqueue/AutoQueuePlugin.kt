package com.six2dez.burp.aiagent.full.autoqueue

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.PluginHost
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SuggestedTargetSink

/**
 * Phase 29 / D-02, BUILD-01, BUILD-04 — the full build's opt-in passive-to-active auto-queue,
 * registered through `META-INF/services/com.six2dez.burp.aiagent.spi.ExtensionPlugin`. The store JAR
 * has neither this class nor that services file, so its passive scan never queues target traffic: the
 * store build shows the suggestions in the core suggested list for the user to queue by hand.
 *
 * Phase 32: the plug-in works next to that core list, it does not replace it. The passive scanner adds
 * every suggestion to the list first and then offers it to this plug-in's sink.
 *
 * [install] puts an [AutoQueueSink] on the passive scanner; [shutdown] removes it, so after an unload
 * the passive scanner holds no path into the active queue.
 *
 * OFF by default for everyone: the sink reads only its own key [KEY], and an absent value is OFF. The
 * 1.0.1 core auto-queue preference (stored as true on most installs, its old default) is never read,
 * so an upgrade does not turn target traffic on behind the user's back (T-29-34).
 */
class AutoQueuePlugin : ExtensionPlugin {
    @Volatile
    private var passiveScanner: PassiveAiScanner? = null

    override fun install(host: PluginHost) {
        host.passiveScanner.suggestedTargetSink =
            AutoQueueSink(host.activeScanner, host.pluginSettings, host.passiveScanner.suggestedTargets, host.log)
        passiveScanner = host.passiveScanner
    }

    override fun shutdown() {
        passiveScanner?.suggestedTargetSink = null
        passiveScanner = null
    }

    companion object {
        /** The auto-queue toggle, written only by [AutoQueueContribution]. Absent means OFF. */
        const val KEY = "full.active.autoqueue.enabled"
    }
}

/**
 * Forwards the passive scanner's suggested targets to the AI Active Scanner, but only while the
 * auto-queue toggle ([AutoQueuePlugin.KEY]) is true AND the active scanner is enabled. The toggle is
 * read on every offer, so a Save takes effect on the next finding. The active scanner's own filters
 * (scope, scan mode, dedup, queue size, AI access policy) still apply to each target in
 * [ActiveAiScanner.tryQueueTarget].
 *
 * The sink counts and logs only the targets the active scanner really queued (31-REVIEW IN-06) and
 * removes exactly those from the core [suggestedTargets] list (Phase 32 D-08). The targets it did not
 * queue stay in the list for the user to queue by hand. While the AI access policy refuses, nothing is
 * queued and nothing is logged here; the active scanner writes its own "Paused" line.
 */
class AutoQueueSink(
    private val activeScanner: ActiveAiScanner,
    private val pluginSettings: PluginSettingsStore,
    private val suggestedTargets: SuggestedTargetList? = null,
    private val log: (String) -> Unit,
) : SuggestedTargetSink {
    override fun offer(
        targets: List<ActiveScanTarget>,
        settings: AgentSettings,
    ) {
        val enabled = pluginSettings.getBoolean(AutoQueuePlugin.KEY) == true
        if (!enabled || !settings.activeAiEnabled) return
        val queued = targets.filter { activeScanner.tryQueueTarget(it) }
        if (queued.isEmpty()) return
        suggestedTargets?.removeAll(queued)
        log("[AutoQueue] Queued ${queued.size} suggested target(s) to the Active Scanner")
    }
}
