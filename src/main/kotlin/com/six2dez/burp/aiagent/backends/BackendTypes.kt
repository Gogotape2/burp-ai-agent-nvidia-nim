package com.six2dez.burp.aiagent.backends

import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.config.AgentSettings

data class BackendLaunchConfig(
    val backendId: String,
    val displayName: String,
    val command: List<String> = emptyList(), // for CLI backends
    val baseUrl: String? = null, // for HTTP backends
    val model: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val requestTimeoutSeconds: Long? = null,
    val sessionId: String? = null,
    val determinismMode: Boolean = false,
    val env: Map<String, String> = emptyMap(),
    val cliSessionId: String? = null, // for CLI session resume (e.g. Claude --resume)
    val contextWindow: Int? = null,
    val transport: MontoyaHttpTransport? = null,
    // REL-04: user-configurable CLI process timeout in seconds; null means use Defaults.CLI_PROCESS_TIMEOUT_SECONDS
    val cliTimeoutSeconds: Int? = null,
)

/**
 * What core knows when it asks a backend to build its own launch configuration
 * ([AiBackend.launchConfig]). Phase 29 / D-09: core builds the configuration of the backends it ships
 * and asks every other backend (the full build's CLI backends, drop-in JARs) for theirs, so core never
 * names a full-only backend id.
 *
 * [baseEnv] holds the variables every backend process gets (session id, determinism flag).
 */
data class LaunchRequest(
    val backendId: String,
    val sessionId: String,
    val determinismMode: Boolean,
    val cliSessionId: String?,
    val settings: AgentSettings?,
    val baseEnv: Map<String, String>,
)

data class ChatMessage(
    val role: String,
    val content: String,
)

data class TokenUsage(
    val inputTokens: Int,
    val outputTokens: Int,
)

sealed class HealthCheckResult {
    data object Healthy : HealthCheckResult()

    data class Degraded(
        val message: String,
    ) : HealthCheckResult()

    data class Unavailable(
        val message: String,
    ) : HealthCheckResult()

    data object Unknown : HealthCheckResult()

    val isHealthy: Boolean
        get() = this is Healthy

    val isReachable: Boolean
        get() = this is Healthy || this is Degraded

    fun summary(): String =
        when (this) {
            Healthy -> "Healthy"
            is Degraded -> "Degraded: $message"
            is Unavailable -> "Unavailable: $message"
            Unknown -> "Unknown"
        }
}

interface AgentConnection {
    fun isAlive(): Boolean

    fun send(
        text: String,
        history: List<ChatMessage>? = null,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        systemPrompt: String? = null,
        jsonMode: Boolean = false,
        maxOutputTokens: Int? = null,
    )

    fun stop()
}

interface UsageAwareConnection {
    fun lastTokenUsage(): TokenUsage?
}

interface JsonModeCapable

interface AiBackend {
    val id: String
    val displayName: String
    val supportsSystemRole: Boolean get() = false

    fun launch(config: BackendLaunchConfig): AgentConnection

    fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean = true

    fun healthCheck(settings: com.six2dez.burp.aiagent.config.AgentSettings): HealthCheckResult = HealthCheckResult.Unknown

    /**
     * The backend's own launch configuration, or `null` to let core build it. Core builds the
     * configuration of the backends it ships; any other backend id is launched with what this returns.
     */
    fun launchConfig(request: LaunchRequest): BackendLaunchConfig? = null

    /** `true` when this backend's health check never leaves the machine, so background polling may run it. */
    val healthCheckIsLocal: Boolean get() = false

    /** Characters per token used to estimate this backend's usage, or `null` for the core default. */
    val charsPerTokenEstimate: Double? get() = null

    /** A user-facing message when [settings] cannot launch this backend, or `null` when they can. */
    fun configurationError(settings: AgentSettings): String? = null

    /** Releases process-wide resources. Called only from [BackendRegistry.shutdown] on extension unload. */
    fun shutdown() {}
}

interface SessionAwareConnection : AgentConnection {
    fun cliSessionId(): String?
}

interface AiBackendFactory {
    fun create(): AiBackend
}
