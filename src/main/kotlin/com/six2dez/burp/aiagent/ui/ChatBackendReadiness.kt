package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings

/**
 * The pre-send readiness check of the chat, split in two so the network half never runs on the EDT
 * (Phase 33 / EDT-01).
 *
 * `ChatPanel` asks [needsProbe] on the EDT. When it answers true, [probe] runs on the named worker
 * `burp-ai-agent-chat-readiness` (through `OffEdtDispatch`) and may perform one loopback health
 * request; [confirm] then runs back on the EDT with the probe's answer and may show a dialog or start
 * the local service. The turn is sent only when [confirm] returns true.
 *
 * Before Phase 33 the whole check ran on the EDT. Its request reached `MontoyaHttpTransport`, which
 * offloads an EDT request and then blocks the EDT on the result, so Burp's UI froze until the local
 * service answered.
 */
interface ChatBackendReadiness {
    /** EDT. True when [settings]'s backend must be probed before a send. Must not block. */
    fun needsProbe(settings: AgentSettings): Boolean

    /** Off the EDT. Probes [settings]'s backend; may perform one loopback request. */
    fun probe(settings: AgentSettings): HealthCheckResult

    /** EDT. Decides from [health] whether the turn may be sent; may prompt the user or start a service. */
    fun confirm(
        settings: AgentSettings,
        health: HealthCheckResult,
    ): Boolean

    companion object {
        /** Never probes and always confirms: the chat sends with no readiness check. */
        val ALWAYS_READY: ChatBackendReadiness =
            object : ChatBackendReadiness {
                override fun needsProbe(settings: AgentSettings): Boolean = false

                override fun probe(settings: AgentSettings): HealthCheckResult = HealthCheckResult.Healthy

                override fun confirm(
                    settings: AgentSettings,
                    health: HealthCheckResult,
                ): Boolean = true
            }
    }
}

/**
 * The readiness check for the two local services, Ollama and LM Studio (Phase 31 D-08/D-09 triggers,
 * unchanged by Phase 33: every other backend sends with no probe).
 *
 * Research OQ2, kept as it was: one loopback health request after the user pressed Send, through the
 * GATE-01 choke point ([backendHealth] is `AgentSupervisor.backendHealth`). [onProbed] paints the
 * result on the status pill, so the probe is also the first-send refresh for these two backends and
 * costs no extra request. [onUnreachable] runs on the EDT and is the "not running, start it now?"
 * decision; its answer is whether the turn is sent.
 */
internal class LocalServiceReadiness(
    private val backendHealth: (AgentSettings) -> HealthCheckResult,
    private val onProbed: (HealthCheckResult) -> Unit,
    private val onUnreachable: (AgentSettings) -> Boolean,
) : ChatBackendReadiness {
    override fun needsProbe(settings: AgentSettings): Boolean = settings.preferredBackendId in PROBED_BACKENDS

    override fun probe(settings: AgentSettings): HealthCheckResult = backendHealth(settings).also(onProbed)

    override fun confirm(
        settings: AgentSettings,
        health: HealthCheckResult,
    ): Boolean = health.isReachable || onUnreachable(settings)

    private companion object {
        val PROBED_BACKENDS = setOf("ollama", "lmstudio")
    }
}
