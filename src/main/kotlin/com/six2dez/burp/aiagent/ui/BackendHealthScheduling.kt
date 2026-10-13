package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory
import com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.LoopbackHost
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

private val checkedAtFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")

private const val DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
private const val DEFAULT_LMSTUDIO_URL = "http://127.0.0.1:1234"

/** Why the AI status pill wants a fresh backend health result. */
enum class HealthCheckTrigger { STARTUP, PERIODIC, SETTINGS_CHANGED, USER_CLICK }

/**
 * Decides which status-pill health checks may run.
 *
 * Remote providers are never polled on a timer: each check is a network call to a third party
 * (and used to be a billable completion), so they are checked only at startup, after a settings or
 * backend change, and when the user clicks the pill. Local backends (a backend whose health check
 * is local, such as Burp AI or a CLI process probe, and HTTP servers on a loopback literal) are cheap
 * to probe and may be polled. Both the startup check and the timer exist only when the injected
 * policy allows unprompted checks (Phase 31 / D-09, D-11); otherwise every check follows a user action.
 */
internal object BackendHealthPolicy {
    /**
     * [backend] is the backend the check would run against. Its own [AiBackend.healthCheckIsLocal]
     * decides first (Burp AI, the full build's CLI process probes); otherwise the URL of a core HTTP
     * backend must be a loopback literal. Phase 29 / D-09: core names no full-only backend id here.
     */
    fun isLocal(
        settings: AgentSettings,
        backend: AiBackend?,
    ): Boolean {
        if (backend?.healthCheckIsLocal == true) return true
        val url =
            when (settings.preferredBackendId) {
                "ollama" -> settings.ollamaUrl.ifBlank { DEFAULT_OLLAMA_URL }
                "lmstudio" -> settings.lmStudioUrl.ifBlank { DEFAULT_LMSTUDIO_URL }
                "openai-compatible" -> settings.openAiCompatibleUrl
                "nvidia-nim" -> settings.nvidiaNimUrl.ifBlank { NvidiaNimBackendFactory.DEFAULT_BASE_URL }
                "perplexity" -> settings.perplexityUrl.ifBlank { PerplexityBackendFactory.DEFAULT_BASE_URL }
                // anthropic and external / unknown backends: never billed by a timer.
                else -> ""
            }
        return url.isNotBlank() && LoopbackHost.isLoopbackUrl(url)
    }

    /**
     * Whether [trigger] may run a check against [backend].
     *
     * [unpromptedAllowed] is the injected policy's answer to "may checks nobody asked for run?"
     * (`AiAccessPolicy.allowsUnpromptedHealthChecks`). When it is false (the BApp Store build, D-09),
     * STARTUP and PERIODIC never run, loopback backends included, so an idle build sends no health
     * request. SETTINGS_CHANGED and USER_CLICK follow a user action and always run. When it is true
     * (the full build, D-11), STARTUP runs for every backend and PERIODIC only for local ones.
     */
    fun shouldRun(
        trigger: HealthCheckTrigger,
        settings: AgentSettings,
        backend: AiBackend?,
        unpromptedAllowed: Boolean,
    ): Boolean =
        when (trigger) {
            HealthCheckTrigger.STARTUP -> unpromptedAllowed
            HealthCheckTrigger.PERIODIC -> unpromptedAllowed && isLocal(settings, backend)
            HealthCheckTrigger.SETTINGS_CHANGED, HealthCheckTrigger.USER_CLICK -> true
        }

    /**
     * Whether a [trigger] that lands while a check is in flight asks [SingleFlightGate] for one re-run.
     * A timer tick does not (the next tick is the re-run); every other trigger does, so a Save or a
     * click mid-check still produces a fresh result.
     */
    fun coalesces(trigger: HealthCheckTrigger): Boolean = trigger != HealthCheckTrigger.PERIODIC

    fun tooltip(
        message: String,
        checkedAt: LocalTime,
    ): String = "$message Last checked ${checkedAt.format(checkedAtFormatter)}. Click to re-check."
}

/**
 * Phase 31 / D-10 — the AI status pill's texts that no health check produced.
 *
 * Before any check runs the pill shows [idleText]: "Not checked · click to test" when the injected
 * policy forbids unprompted checks (nothing will check until the user acts), otherwise the legacy
 * "AI: ?" (the startup check is about to replace it). [AI_DISABLED] is painted from a local policy
 * read when the selected backend is refused, with no request.
 */
internal object BackendPill {
    const val NOT_CHECKED = "Not checked · click to test"
    const val AI_DISABLED = "AI disabled in Burp"
    const val UNCHECKED_LEGACY = "AI: ?"

    fun idleText(unpromptedAllowed: Boolean): String = if (unpromptedAllowed) UNCHECKED_LEGACY else NOT_CHECKED

    fun isRefusal(error: Throwable?): Boolean = false

    fun healthOfTurn(error: Throwable?): HealthCheckResult = HealthCheckResult.Healthy
}

/**
 * Runs at most one task at a time on [executor].
 *
 * A submit that lands while a task is in flight is refused; when it asked to [submit]'s `coalesce`,
 * [onRerun] fires exactly once after the flight ends, so a Settings save or a click that arrives
 * mid-check still produces a fresh result instead of being lost. A task that throws, or an executor
 * that rejects the task, always leaves the gate released.
 */
internal class SingleFlightGate(
    private val executor: Executor,
    private val onRerun: () -> Unit,
) {
    private val running = AtomicBoolean(false)
    private val rerunRequested = AtomicBoolean(false)

    fun submit(
        coalesce: Boolean,
        task: () -> Unit,
    ): Boolean {
        if (!running.compareAndSet(false, true)) {
            if (coalesce) rerunRequested.set(true)
            return false
        }
        return try {
            executor.execute {
                try {
                    task()
                } finally {
                    running.set(false)
                    if (rerunRequested.getAndSet(false)) onRerun()
                }
            }
            true
        } catch (_: RejectedExecutionException) {
            running.set(false)
            false
        }
    }
}
