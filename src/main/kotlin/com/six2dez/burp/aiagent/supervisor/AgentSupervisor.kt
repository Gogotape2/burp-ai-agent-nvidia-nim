package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.LaunchRequest
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class AgentSupervisor(
    private val api: MontoyaApi,
    private val registry: BackendRegistry,
    private val audit: AuditLogger,
    // Phase 29 / BUILD-04: no default value on purpose (Pitfall 11). Every caller, tests included,
    // states which flavor's access policy it runs under, so none silently inherits one.
    private val aiAccessPolicy: AiAccessPolicy,
) {
    var aiRequestLogger: AiRequestLogger? = null

    /**
     * Phase 29 / D-06: the plug-in settings store handed to [com.six2dez.burp.aiagent.spi.BackendModelHint]
     * providers. App sets it once at startup; null (tests, or before wiring) means no hint is asked.
     */
    @Volatile
    var pluginSettings: PluginSettingsStore? = null

    // Loaded once. The store build ships no provider; the full build's CLI plug-in answers for ollama.
    private val modelHints: List<BackendModelHint> = Plugins.load(BackendModelHint::class.java)

    data class Status(
        val state: String,
        val backendId: String?,
    )

    data class BackendInfo(
        val backendId: String,
        val displayName: String,
        val model: String?,
    )

    private sealed class AgentState {
        data object Idle : AgentState()

        data class Starting(
            val backendId: String,
        ) : AgentState()

        data class Running(
            val backendId: String,
            val sessionId: String,
            val connection: AgentConnection,
            val launchConfig: BackendLaunchConfig,
        ) : AgentState()
    }

    private val stateRef = AtomicReference<AgentState>(AgentState.Idle)
    private val settingsRef = AtomicReference<AgentSettings?>(null)
    private val lastErrorRef = AtomicReference<String?>(null)
    private val chatSessionManager = ChatSessionManager()

    // Phase 31 / GATE-01: the one transport production builds, unbound and gated by the injected
    // policy. aiAccessRefusal re-reads Burp's "Use AI" on every call, so each request is judged when it
    // is about to leave (D-04), with no watcher. Backends only ever receive views bound by core.
    internal val httpTransport = MontoyaHttpTransport(api) { backendId -> aiAccessRefusal(backendId) }

    private val services = java.util.concurrent.ConcurrentHashMap<String, Process>()
    private val lifecycleLock = ReentrantLock()

    // UI-SPEC PC-4: saved backend ids already reported as substituted during this extension load.
    private val substitutedBackendIds: MutableSet<String> =
        java.util.concurrent.ConcurrentHashMap
            .newKeySet()

    init {
        // BUG-69-01: HTTP backends' health checks must use Burp's HTTP stack (upstream proxy /
        // SOCKS / cert store). The registry remembers the transport and re-applies it to every
        // HttpTransportAware backend on reload(), so a Settings save no longer drops it.
        registry.setHttpTransport(httpTransport)
    }

    fun applySettings(settings: AgentSettings) {
        settingsRef.set(settings)
    }

    /**
     * Returns the state of Burp Pro's built-in **"Use AI" for extensions** preference (always `false`
     * in Burp Community, where the preference does not exist).
     *
     * Which backends need it is decided by the injected [AiAccessPolicy], not here: the BApp Store
     * build requires it for every backend, the full build only for `burp-ai`. Callers gating start /
     * send paths should use [aiAccessRefusal], never this raw value.
     */
    fun isAiEnabled(): Boolean =
        try {
            api.ai().isEnabled()
        } catch (_: Exception) {
            // INTENTIONAL: Burp AI API unavailable in Community edition; fallback returns false
            false
        }

    /**
     * `null` when the injected [AiAccessPolicy] allows a request to [backendId] under the current
     * value of Burp's `Use AI` preference; otherwise the user-facing refusal message. Start / send
     * paths short-circuit on a non-null result and surface the message as the error.
     */
    fun aiAccessRefusal(backendId: String): String? = aiAccessPolicy.refusal(backendId, isAiEnabled())

    /**
     * `true` iff a backend is running AND the [AiAccessPolicy] currently refuses it. Returns false
     * when no backend is running. Background scanners use this to skip work that would fail at send
     * time.
     */
    fun isBlockedByAiAccessPolicy(): Boolean {
        val running = stateRef.get() as? AgentState.Running ?: return false
        return aiAccessRefusal(running.backendId) != null
    }

    fun currentSessionId(): String? = (stateRef.get() as? AgentState.Running)?.sessionId

    fun lastStartError(): String? = lastErrorRef.get()

    fun startOrAttach(backendId: String): Boolean {
        // Phase 29 / D-08: an unregistered saved id runs on burp-ai, and the policy judges that backend.
        val resolvedId = resolveBackendId(backendId)
        val refusal = aiAccessRefusal(resolvedId)
        if (refusal != null) {
            lastErrorRef.set(refusal)
            api.logging().logToOutput(refusal)
            return false
        }

        // Phase 1: Acquire lock, transition state, prepare config — then release lock
        val backend: com.six2dez.burp.aiagent.backends.AiBackend
        val sessionId: String
        val launchConfig: BackendLaunchConfig
        val startingState: AgentState.Starting

        lifecycleLock.withLock {
            lastErrorRef.set(null)

            // Check if already running the requested backend
            val current = stateRef.get()
            if (current is AgentState.Running && current.backendId == resolvedId && current.connection.isAlive()) {
                return true
            }

            // Reject if another start is in progress
            if (current is AgentState.Starting) {
                val msg = "Backend startup already in progress: ${current.backendId}"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                return false
            }

            stop()

            val resolved = registry.get(resolvedId)
            if (resolved == null) {
                val msg = "Backend not found: $resolvedId"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                return false
            }
            backend = resolved

            sessionId = "session-" + UUID.randomUUID().toString()
            launchConfig = buildLaunchConfig(resolvedId, sessionId)

            // Set transitional STARTING state before releasing lock.
            // Keep a reference for the CAS below (AtomicReference uses identity comparison).
            startingState = AgentState.Starting(resolvedId)
            stateRef.set(startingState)
        }

        // Phase 2: Launch backend outside lock (may block for CLI processes)
        return try {
            api.logging().logToOutput("Launching backend $resolvedId with config: ${redactedConfigSummary(launchConfig)}")
            val conn = backend.launch(launchConfig)

            val newState =
                AgentState.Running(
                    backendId = resolvedId,
                    sessionId = sessionId,
                    connection = conn,
                    launchConfig = launchConfig,
                )

            // Only transition if still in STARTING state (stop() may have been called).
            // Uses the same instance reference set above — AtomicReference.compareAndSet
            // checks identity (===), not structural equality.
            if (stateRef.compareAndSet(startingState, newState)) {
                audit.logEvent(
                    "session_start",
                    mapOf(
                        "backendId" to resolvedId,
                        "sessionId" to sessionId,
                        "model" to launchConfig.model,
                        "displayName" to launchConfig.displayName,
                    ),
                )
                true
            } else {
                // Another thread called stop() while we were launching — clean up
                conn.stop()
                false
            }
        } catch (e: Exception) {
            val msg = "[AgentSupervisor] Failed to launch backend $resolvedId: ${e.message}"
            lastErrorRef.set(msg)
            api.logging().logToError(msg)
            // Reset to Idle if still in STARTING
            stateRef.compareAndSet(startingState, AgentState.Idle)
            false
        }
    }

    fun isOllamaHealthy(settings: AgentSettings): Boolean = registry.healthCheck("ollama", settings).isReachable

    fun startOllamaService(settings: AgentSettings): Boolean {
        val cmd = settings.ollamaServeCmd
        if (cmd.isBlank()) {
            api.logging().logToError("Ollama serve command is empty.")
            return false
        }
        return startService("ollama-serve", cmd)
    }

    fun isLmStudioHealthy(settings: AgentSettings): Boolean = registry.healthCheck("lmstudio", settings).isReachable

    fun startLmStudioService(settings: AgentSettings): Boolean {
        val cmd = settings.lmStudioServerCmd
        if (cmd.isBlank()) {
            api.logging().logToError("LM Studio server command is empty.")
            return false
        }
        return startService("lmstudio-server", cmd)
    }

    fun isBackendHealthy(settings: AgentSettings): Boolean = backendHealth(settings).isHealthy

    fun backendHealth(settings: AgentSettings): HealthCheckResult = registry.healthCheck(resolveBackendId(settings.preferredBackendId), settings)

    /**
     * Phase 29 / D-08: [backendId] when the registry has it, otherwise the default backend (burp-ai).
     * Logs C-N9 to the Output tab once per substituted id per extension load (UI-SPEC S24 / PC-4), as
     * plain text: the Output pane renders no HTML. The substitution is never persisted.
     */
    private fun resolveBackendId(backendId: String): String {
        if (registry.get(backendId) != null) return backendId
        val fallback = BackendRegistry.DEFAULT_BACKEND_ID
        if (backendId != fallback && substitutedBackendIds.add(backendId)) {
            safeLogOutput("[AgentSupervisor] Saved backend '$backendId' is not registered in this build; using $fallback.")
        }
        return fallback
    }

    fun stop() {
        lifecycleLock.withLock {
            val prev = stateRef.getAndSet(AgentState.Idle)
            when (prev) {
                is AgentState.Running -> {
                    prev.connection.stop()
                    audit.logEvent("session_stop", mapOf("backendId" to prev.backendId))
                }
                is AgentState.Starting -> {
                    // Launch in progress — state set to Idle; the launching thread
                    // will detect the CAS failure and clean up the connection.
                    audit.logEvent("session_stop", mapOf("backendId" to prev.backendId, "note" to "cancelled_during_start"))
                }
                is AgentState.Idle -> { /* nothing */ }
            }
        }
    }

    fun send(
        text: String,
        history: List<com.six2dez.burp.aiagent.backends.ChatMessage>? = null,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        traceId: String? = null,
        systemPrompt: String? = null,
        jsonMode: Boolean = false,
        maxOutputTokens: Int? = null,
    ) {
        val current = stateRef.get()
        if (current !is AgentState.Running) {
            onComplete(IllegalStateException("No active session"))
            return
        }
        val refusal = aiAccessRefusal(current.backendId)
        if (refusal != null) {
            onComplete(AiAccessRefusedException(refusal))
            return
        }

        if (!current.connection.isAlive()) {
            onComplete(IllegalStateException("Session is not alive"))
            return
        }

        val sessionId = current.sessionId
        val backendId = current.backendId
        val launchConfig = current.launchConfig
        val resolvedTraceId = traceId ?: "agent-turn-" + UUID.randomUUID().toString()

        if (audit.isEnabled()) {
            val bundle =
                audit.buildPromptBundle(
                    sessionId = sessionId,
                    backendId = backendId,
                    backendConfig = launchConfig,
                    promptText = text,
                    contextJson = contextJson,
                    privacyMode = privacyMode,
                    determinismMode = determinismMode,
                )
            audit.logEvent("prompt", bundle)
            audit.writePromptBundle(bundle)
        }

        api.logging().logToOutput("AI send: backend=$backendId session=$sessionId")
        api.logging().logToOutput("AI connection: ${current.connection.javaClass.name}")

        val sendStartMs = System.currentTimeMillis()
        aiRequestLogger?.log(
            type = ActivityType.PROMPT_SENT,
            source = "agent",
            backendId = backendId,
            sessionId = sessionId,
            detail = "Prompt sent (${text.length} chars)",
            promptChars = text.length,
            metadata =
                mapOf(
                    "operation" to "agent_send",
                    "status" to "sent",
                    "traceId" to resolvedTraceId,
                ),
        )

        val responseAccumulator = StringBuilder()
        current.connection.send(
            text,
            history = history,
            onChunk = { chunk ->
                responseAccumulator.append(chunk)
                if (audit.isEnabled()) {
                    audit.logEvent("agent_chunk", mapOf("backendId" to backendId) + audit.bodyFields("chunk", chunk))
                }
                onChunk(chunk)
            },
            jsonMode = jsonMode,
            maxOutputTokens = maxOutputTokens,
            onComplete = { err ->
                val durationMs = System.currentTimeMillis() - sendStartMs
                audit.logEvent(
                    "prompt_complete",
                    mapOf("backendId" to backendId, "status" to (if (err == null) "ok" else "error")) + audit.errorFields(err),
                )
                if (err != null) {
                    api.logging().logToError("AI backend error ($backendId): ${err.message}")
                    aiRequestLogger?.log(
                        type = ActivityType.ERROR,
                        source = "agent",
                        backendId = backendId,
                        sessionId = sessionId,
                        detail = "Error: ${err.message}",
                        durationMs = durationMs,
                        promptChars = text.length,
                        metadata =
                            mapOf(
                                "operation" to "agent_send",
                                "status" to "error",
                                "traceId" to resolvedTraceId,
                                "errorClass" to err.javaClass.simpleName,
                                "errorCode" to err.javaClass.simpleName,
                            ),
                    )
                } else {
                    aiRequestLogger?.log(
                        type = ActivityType.RESPONSE_COMPLETE,
                        source = "agent",
                        backendId = backendId,
                        sessionId = sessionId,
                        detail = "Response received (${responseAccumulator.length} chars)",
                        durationMs = durationMs,
                        promptChars = text.length,
                        responseChars = responseAccumulator.length,
                        metadata =
                            mapOf(
                                "operation" to "agent_send",
                                "status" to "ok",
                                "traceId" to resolvedTraceId,
                            ),
                    )
                }
                onComplete(err)
            },
            systemPrompt = systemPrompt,
        )
    }

    fun sendChat(
        chatSessionId: String,
        backendId: String,
        text: String,
        history: List<com.six2dez.burp.aiagent.backends.ChatMessage>? = null,
        contextJson: String?,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        traceId: String? = null,
        systemPrompt: String? = null,
        maxOutputTokens: Int? = null,
        launchMetadata: Map<String, String>? = null,
    ): com.six2dez.burp.aiagent.backends.AgentConnection? {
        // Phase 29 / D-08: an unregistered saved id runs on burp-ai, and the policy judges that backend.
        val resolvedId = resolveBackendId(backendId)
        val refusal = aiAccessRefusal(resolvedId)
        if (refusal != null) {
            onComplete(AiAccessRefusedException(refusal))
            return null
        }

        lastErrorRef.set(null)
        val resolvedTraceId = traceId ?: "chat-turn-" + UUID.randomUUID().toString()
        val backend = registry.get(resolvedId)
        if (backend == null) {
            onComplete(IllegalStateException("Backend not found: $resolvedId"))
            return null
        }

        // Hoisted so the audit bundle (below) can read backend config in both
        // existing-connection and new-connection paths.
        val cliSessionId = chatSessionManager.cliSessionIdFor(chatSessionId, resolvedId)
        val launchConfig =
            buildLaunchConfig(
                resolvedId,
                chatSessionId,
                cliSessionId = cliSessionId,
            )

        // Try to reuse an existing connection (for HTTP backends with conversation history)
        val existingConn = chatSessionManager.existingConnectionFor(chatSessionId, resolvedId)
        val connection: AgentConnection
        if (existingConn != null) {
            connection = existingConn
        } else {
            try {
                connection = backend.launch(launchConfig)
            } catch (e: Exception) {
                val msg = "[AgentSupervisor] Failed to launch backend $resolvedId: ${e.message}"
                lastErrorRef.set(msg)
                api.logging().logToError(msg)
                onComplete(e)
                return null
            }
        }

        if (audit.isEnabled()) {
            val bundle =
                audit.buildPromptBundle(
                    sessionId = chatSessionId,
                    backendId = resolvedId,
                    backendConfig = launchConfig,
                    promptText = text,
                    contextJson = contextJson,
                    privacyMode = privacyMode,
                    determinismMode = determinismMode,
                    promptSource = launchMetadata?.get("promptSource"),
                    promptId = launchMetadata?.get("promptId"),
                    promptTitle = launchMetadata?.get("promptTitle"),
                    contextKind = launchMetadata?.get("contextKind"),
                )
            audit.logEvent("prompt", bundle)
            audit.writePromptBundle(bundle)
        }

        api.logging().logToOutput("AI chat send: backend=$resolvedId chatSession=$chatSessionId")

        val chatSendStartMs = System.currentTimeMillis()
        aiRequestLogger?.log(
            type = ActivityType.PROMPT_SENT,
            source = "chat",
            backendId = resolvedId,
            sessionId = chatSessionId,
            detail = "Chat prompt sent (${text.length} chars)",
            promptChars = text.length,
            metadata =
                mapOf(
                    "operation" to "chat_turn",
                    "status" to "sent",
                    "traceId" to resolvedTraceId,
                ) + launchMetadata.orEmpty(),
        )

        val chatResponseAccumulator = StringBuilder()
        connection.send(
            text,
            history = history,
            onChunk = { chunk ->
                chatResponseAccumulator.append(chunk)
                if (audit.isEnabled()) {
                    audit.logEvent("agent_chunk", mapOf("backendId" to resolvedId) + audit.bodyFields("chunk", chunk))
                }
                onChunk(chunk)
            },
            systemPrompt = systemPrompt,
            maxOutputTokens = maxOutputTokens,
            onComplete = { err ->
                val durationMs = System.currentTimeMillis() - chatSendStartMs
                audit.logEvent(
                    "prompt_complete",
                    mapOf("backendId" to resolvedId, "status" to (if (err == null) "ok" else "error")) + audit.errorFields(err),
                )
                if (err != null) {
                    api.logging().logToError("AI backend error ($resolvedId): ${err.message}")
                    aiRequestLogger?.log(
                        type = ActivityType.ERROR,
                        source = "chat",
                        backendId = resolvedId,
                        sessionId = chatSessionId,
                        detail = "Chat error: ${err.message}",
                        durationMs = durationMs,
                        promptChars = text.length,
                        metadata =
                            mapOf(
                                "operation" to "chat_turn",
                                "status" to "error",
                                "traceId" to resolvedTraceId,
                                "errorClass" to err.javaClass.simpleName,
                                "errorCode" to err.javaClass.simpleName,
                            ) + launchMetadata.orEmpty(),
                    )
                } else {
                    aiRequestLogger?.log(
                        type = ActivityType.RESPONSE_COMPLETE,
                        source = "chat",
                        backendId = resolvedId,
                        sessionId = chatSessionId,
                        detail = "Chat response received (${chatResponseAccumulator.length} chars)",
                        durationMs = durationMs,
                        promptChars = text.length,
                        responseChars = chatResponseAccumulator.length,
                        metadata =
                            mapOf(
                                "operation" to "chat_turn",
                                "status" to "ok",
                                "traceId" to resolvedTraceId,
                            ) + launchMetadata.orEmpty(),
                    )
                }
                // Update session state after completion (stores cliSessionId or connection for reuse)
                chatSessionManager.updateSession(chatSessionId, resolvedId, connection)
                onComplete(err)
            },
        )
        return connection
    }

    fun getBackend(backendId: String): com.six2dez.burp.aiagent.backends.AiBackend? = registry.get(backendId)

    fun removeChatSession(chatSessionId: String) {
        chatSessionManager.removeSession(chatSessionId)
    }

    /** Shutdown all live chat connections (e.g. on project change). */
    fun shutdownAllChatSessions() {
        chatSessionManager.shutdown()
    }

    fun status(): Status {
        val current = stateRef.get()
        return when (current) {
            is AgentState.Idle -> Status("Idle", null)
            is AgentState.Starting -> Status("Starting", current.backendId)
            is AgentState.Running -> {
                if (current.connection.isAlive()) {
                    Status("Running", current.backendId)
                } else {
                    Status("Crashed", current.backendId)
                }
            }
        }
    }

    fun getCurrentBackendInfo(): BackendInfo? {
        val current = stateRef.get()
        if (current !is AgentState.Running) return null

        val config = current.launchConfig
        return BackendInfo(
            backendId = current.backendId,
            displayName = config.displayName,
            model = config.model,
        )
    }

    // Suppressed here rather than baselined (ADR-17 forbids new baseline entries): one branch per
    // backend core ships. Phase 29 / D-09: every other backend (the full build's CLI backends, drop-in
    // JARs) builds its own configuration through AiBackend.launchConfig, in the `else` branch.
    @Suppress("CyclomaticComplexMethod", "LongMethod")
    private fun buildLaunchConfig(
        backendId: String,
        sessionId: String,
        cliSessionId: String? = null,
    ): BackendLaunchConfig {
        val prefs = api.persistence().preferences()
        val settings = settingsRef.get()
        val determinism = settings?.determinismMode ?: (prefs.getBoolean("determinism.enabled") ?: false)

        val baseEnv =
            mapOf(
                "BURP_AI_AGENT_SESSION_ID" to sessionId,
                "BURP_AI_AGENT_DETERMINISM" to determinism.toString(),
            )
        // Phase 31 / GATE-01: core binds the backend id the egress gate judges; no backend chooses it.
        val transport = httpTransport.forBackend(backendId)

        return when (backendId) {
            "burp-ai" ->
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Burp AI (built-in)",
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    transport = transport,
                )
            "ollama" -> {
                val url = (settings?.ollamaUrl ?: prefs.getString("ollama.url") ?: "http://127.0.0.1:11434").trim()
                val explicitModel = (settings?.ollamaModel ?: prefs.getString("ollama.model")).orEmpty().trim()
                val model = explicitModel.ifBlank { hintedModel("ollama") ?: DEFAULT_OLLAMA_MODEL }
                val apiKey = settings?.ollamaApiKey ?: prefs.getString("ollama.apiKey").orEmpty()
                val rawHeaders = settings?.ollamaHeaders ?: prefs.getString("ollama.headers").orEmpty()
                val headers =
                    HeaderParser.withBearerToken(
                        apiKey,
                        HeaderParser.parse(rawHeaders),
                    )
                val timeoutSeconds =
                    settings?.ollamaTimeoutSeconds
                        ?: (prefs.getInteger("ollama.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Ollama",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    contextWindow =
                        settings?.ollamaContextWindow
                            ?: prefs.getInteger("ollama.contextWindow"),
                    transport = transport,
                )
            }
            "lmstudio" -> {
                val url = (settings?.lmStudioUrl ?: prefs.getString("lmstudio.url") ?: "http://127.0.0.1:1234").trim()
                val model = (settings?.lmStudioModel ?: prefs.getString("lmstudio.model") ?: "lmstudio").trim()
                val timeoutSeconds =
                    settings?.lmStudioTimeoutSeconds
                        ?: (prefs.getInteger("lmstudio.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.lmStudioApiKey ?: prefs.getString("lmstudio.apiKey").orEmpty()
                val rawHeaders = settings?.lmStudioHeaders ?: prefs.getString("lmstudio.headers").orEmpty()
                val headers =
                    HeaderParser.withBearerToken(
                        apiKey,
                        HeaderParser.parse(rawHeaders),
                    )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "LM Studio",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    transport = transport,
                )
            }
            "openai-compatible" -> {
                val url = (settings?.openAiCompatibleUrl ?: prefs.getString("openai.compat.url") ?: "").trim()
                val model = (settings?.openAiCompatibleModel ?: prefs.getString("openai.compat.model") ?: "").trim()
                val timeoutSeconds =
                    settings?.openAiCompatibleTimeoutSeconds
                        ?: (prefs.getInteger("openai.compat.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.openAiCompatibleApiKey ?: prefs.getString("openai.compat.apiKey").orEmpty()
                val rawHeaders = settings?.openAiCompatibleHeaders ?: prefs.getString("openai.compat.headers").orEmpty()
                val headers =
                    HeaderParser.withBearerToken(
                        apiKey,
                        HeaderParser.parse(rawHeaders),
                    )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Generic (OpenAI-compatible)",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    transport = transport,
                )
            }
            "nvidia-nim" -> {
                val url = (settings?.nvidiaNimUrl ?: prefs.getString("nvidia.nim.url") ?: "https://integrate.api.nvidia.com").trim()
                val model = (settings?.nvidiaNimModel ?: prefs.getString("nvidia.nim.model") ?: "").trim()
                val timeoutSeconds =
                    settings?.nvidiaNimTimeoutSeconds
                        ?: (prefs.getInteger("nvidia.nim.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.nvidiaNimApiKey ?: prefs.getString("nvidia.nim.apiKey").orEmpty()
                val rawHeaders = settings?.nvidiaNimHeaders ?: prefs.getString("nvidia.nim.headers").orEmpty()
                val headers =
                    HeaderParser.withBearerToken(
                        apiKey,
                        HeaderParser.parse(rawHeaders),
                    )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "NVIDIA NIM",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    // BUG-69-01: NVIDIA NIM is an OpenAiCompatibleBackend instance whose send()
                    // now fails fast on transport == null. Pass the bound transport so production calls
                    // route through Burp's HTTP stack (issue #69) instead of throwing.
                    transport = transport,
                )
            }
            "perplexity" -> {
                val url = (settings?.perplexityUrl ?: prefs.getString("perplexity.url") ?: "https://api.perplexity.ai").trim()
                val model = (settings?.perplexityModel ?: prefs.getString("perplexity.model") ?: "").trim()
                val timeoutSeconds =
                    settings?.perplexityTimeoutSeconds
                        ?: (prefs.getInteger("perplexity.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
                val apiKey = settings?.perplexityApiKey ?: prefs.getString("perplexity.apiKey").orEmpty()
                val rawHeaders = settings?.perplexityHeaders ?: prefs.getString("perplexity.headers").orEmpty()
                val headers =
                    HeaderParser.withBearerToken(
                        apiKey,
                        HeaderParser.parse(rawHeaders),
                    )
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Perplexity",
                    baseUrl = url,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    // BUG-69-01: Perplexity is also an OpenAiCompatibleBackend instance whose
                    // send() now fails fast on transport == null. Pass the bound transport for the same
                    // reason as NVIDIA NIM.
                    transport = transport,
                )
            }
            "anthropic" -> {
                // PATTERNS Planner Note 1: the supervisor must build x-api-key/anthropic-version
                // headers here (NOT withBearerToken — Pitfall 2). Without this branch the backend
                // receives empty headers and the API key is never sent.
                val model = (settings?.anthropicModel ?: prefs.getString("anthropic.model") ?: "claude-sonnet-4-6").trim()
                val apiKey = settings?.anthropicApiKey ?: prefs.getString("anthropic.apiKey").orEmpty()
                val timeoutSeconds =
                    prefs.getInteger("anthropic.timeoutSeconds") ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = "Anthropic",
                    model = model,
                    headers = mapOf("x-api-key" to apiKey, "anthropic-version" to "2023-06-01"),
                    requestTimeoutSeconds = timeoutSeconds.toLong(),
                    sessionId = sessionId,
                    determinismMode = determinism,
                    env = baseEnv,
                    cliSessionId = cliSessionId,
                    // BUG-69-01: route through Burp's HTTP stack so traffic appears in Proxy history (SC2).
                    transport = transport,
                )
            }
            else ->
                registry.get(backendId)?.launchConfig(
                    LaunchRequest(
                        backendId = backendId,
                        sessionId = sessionId,
                        determinismMode = determinism,
                        cliSessionId = cliSessionId,
                        settings = settings,
                        baseEnv = baseEnv,
                    ),
                ) ?: BackendLaunchConfig(backendId, backendId, env = baseEnv, cliSessionId = cliSessionId)
        }
    }

    /**
     * Phase 29 / D-06: the first non-blank model a [BackendModelHint] plug-in suggests for [backendId],
     * or null. A hint that throws is logged and skipped, so a broken plug-in cannot stop a launch
     * (TooGenericExceptionCaught is suppressed for that reason: a plug-in may throw anything).
     */
    @Suppress("TooGenericExceptionCaught")
    private fun hintedModel(backendId: String): String? {
        val store = pluginSettings ?: return null
        return modelHints.firstNotNullOfOrNull { hint ->
            try {
                hint.defaultModel(backendId, store)?.trim()?.takeIf { it.isNotEmpty() }
            } catch (e: Exception) {
                api.logging().logToError("[AgentSupervisor] Model hint ${hint.javaClass.name} failed: ${e.message}")
                null
            }
        }
    }

    private fun startService(
        name: String,
        cmd: String,
    ): Boolean {
        val existing = services[name]
        if (existing != null && existing.isAlive) return true
        val parts = tokenizeCommand(cmd)
        if (parts.isEmpty()) return false
        return try {
            val process =
                ProcessBuilder(parts)
                    .redirectErrorStream(true)
                    .start()
            services[name] = process
            // REL-07 / SC6: this pump calls reader.forEachLine, which occupies its thread for the
            // ENTIRE lifetime of the service process. Unbounded-duration work belongs on its own
            // dedicated, named daemon thread (Phase 23 D-05), never on a shared pool where it would
            // park a worker for as long as the service runs.
            val pumpThread =
                Thread({
                    try {
                        process.inputStream.bufferedReader().use { reader ->
                            reader.forEachLine { line ->
                                safeLogOutput("[$name] $line")
                            }
                        }
                    } catch (e: Exception) {
                        safeLogOutput("[$name] output stream closed: ${e.message}")
                    }
                }, "burp-ai-agent-service-$name")
            // Phase 23 D-05: set explicitly. "A daemon thread never blocks unload" only holds if the
            // flag is actually set — a non-daemon pump would keep the JVM alive after Burp quits.
            pumpThread.isDaemon = true
            pumpThread.start()
            safeLogOutput("Started service: $name")
            true
        } catch (e: Exception) {
            safeLogError("[AgentSupervisor] Failed to start service $name: ${e.message}")
            false
        }
    }

    /**
     * Returns a safe diagnostic string for [config] that includes structural/connection details
     * (backend ID, display name, model, base URL, header key names) but never exposes header
     * values such as API keys or Bearer tokens. Used by logToOutput and audit session_start events.
     */
    private fun redactedConfigSummary(config: BackendLaunchConfig): String =
        "BackendLaunchConfig(backendId=${config.backendId}, displayName=${config.displayName}, " +
            "model=${config.model}, baseUrl=${config.baseUrl}, " +
            "headers=[${config.headers.keys.joinToString()}])"

    private fun safeLogOutput(message: String) {
        try {
            api.logging().logToOutput(message)
        } catch (_: Throwable) {
            // INTENTIONAL: safeLogOutput fallback must not throw; stderr is the last resort
            System.err.println(message)
        }
    }

    private fun safeLogError(message: String) {
        try {
            api.logging().logToError(message)
        } catch (_: Throwable) {
            // INTENTIONAL: safeLogError fallback must not throw; stderr is the last resort
            System.err.println(message)
        }
    }

    fun shutdown() {
        stop()
        chatSessionManager.shutdown()
        for ((name, process) in services) {
            try {
                process.destroyForcibly()
            } catch (e: Exception) {
                safeLogError("[AgentSupervisor] Failed to terminate service '$name': ${e.message}")
            }
        }
        services.clear()
    }

    companion object {
        /** The Ollama model when the user left the field blank and no plug-in suggests one. */
        private const val DEFAULT_OLLAMA_MODEL = "llama3.1"

        /**
         * Splits a user-typed command string into argv tokens with quote and backslash handling.
         *
         * Shared between [AgentSupervisor]'s service launch paths and the full build's CLI backend (its
         * `isAvailable()` and its launch configuration), so that the executable resolved by
         * `isAvailable()` is the same as the one launched by `send()` (fixes bug #67).
         *
         * On Windows the backslash is the path separator and MUST NOT be interpreted as an escape
         * character — otherwise paths like `C:\Users\u\bin\claude.exe` collapse to `C:Usersubinclaude.exe`.
         * On Unix the historical POSIX-ish escape behavior is preserved, but only outside quoted
         * strings (inside double or single quotes the backslash is taken literally).
         *
         * The `isWindows` flag is parametrized so the function is deterministically testable on any
         * host; production callers rely on the runtime-OS default.
         */
        internal fun tokenizeCommand(
            command: String,
            isWindows: Boolean = System.getProperty("os.name").lowercase(java.util.Locale.ROOT).contains("win"),
        ): List<String> {
            val tokens = mutableListOf<String>()
            val currentToken = StringBuilder()
            var inQuotes = false
            var quoteChar = ' '

            var i = 0
            while (i < command.length) {
                val c = command[i]
                when {
                    // Skip the escape branch on Windows (backslash is the path separator) and when
                    // inside quoted strings on Unix (POSIX double/single quotes take backslashes
                    // literally outside of a few special cases we do not need to model here).
                    c == '\\' && !isWindows && !inQuotes && i + 1 < command.length -> {
                        currentToken.append(command[i + 1])
                        i++
                    }
                    (c == '"' || c == '\'') -> {
                        if (inQuotes) {
                            if (c == quoteChar) {
                                inQuotes = false
                            } else {
                                currentToken.append(c)
                            }
                        } else {
                            inQuotes = true
                            quoteChar = c
                        }
                    }
                    c.isWhitespace() -> {
                        if (inQuotes) {
                            currentToken.append(c)
                        } else if (currentToken.isNotEmpty()) {
                            tokens.add(currentToken.toString())
                            currentToken.clear()
                        }
                    }
                    else -> {
                        currentToken.append(c)
                    }
                }
                i++
            }
            if (currentToken.isNotEmpty()) {
                tokens.add(currentToken.toString())
            }
            return tokens
        }
    }
}
