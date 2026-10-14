package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory
import com.six2dez.burp.aiagent.backends.burpai.BurpAiBackend
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory
import com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory
import com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.spi.ExternalBackendSource
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.util.TokenTracker
import java.util.ServiceLoader
import java.util.concurrent.ConcurrentHashMap

// TooManyFunctions: Phase 29 / D-08 added isRegistered and resolve, the registry's lookup API; splitting
// the lookup off the class that owns the map would not make either part simpler. Phase 31 / D-14 moved
// the drop-in loader's two functions to src/full and added guardedSource, so detekt counts 14 (was 15)
// against its threshold of 11. Suppressed locally because ADR-17 forbids new baseline entries.
@Suppress("TooManyFunctions")
class BackendRegistry internal constructor(
    private val api: MontoyaApi,
    private val externalSources: List<ExternalBackendSource>,
) {
    private val backends = ConcurrentHashMap<String, AiBackend>()
    private val availabilityCache = ConcurrentHashMap<Pair<String, Int>, Boolean>()

    // BUG-69-01: Burp's HTTP transport for HTTP backends' health checks. The registry owns it so
    // reload() (the Settings save path) re-applies it to the freshly created instances. Phase 31 /
    // GATE-01: each HttpTransportAware backend receives a view bound to its own id (forBackend), so the
    // egress gate judges the id core assigned, never one a backend reports. Declared
    // above `init` on purpose: Kotlin runs initializers in declaration order, so a property placed
    // after `init { reload() }` would be initialized after the first reload.
    @Volatile
    private var httpTransport: MontoyaHttpTransport? = null

    // Phase 29 / D-06: the plug-in settings store for backends whose configuration lives in plug-in keys
    // (the full build's CLI backends). Remembered and re-applied on reload, like the HTTP transport, and
    // declared above `init` for the same reason.
    @Volatile
    private var pluginSettings: PluginSettingsStore? = null

    init {
        reload()
    }

    // Phase 31 / D-14 (WR-05, ADR-18 OQ8): sources of backends loaded from outside the extension JAR.
    // Only the full build registers one, the drop-in loader (src/full); the store classpath has no
    // provider, so the store build never creates, lists or loads a drop-in directory. The internal
    // constructor exists so tests can pass their own sources (Phase 31 gap closure WR-06).
    constructor(api: MontoyaApi) : this(api, Plugins.load(ExternalBackendSource::class.java))

    /** Remembers [transport] and injects it into every current and future [HttpTransportAware] backend. */
    @Synchronized
    fun setHttpTransport(transport: MontoyaHttpTransport) {
        httpTransport = transport
        applyHttpTransport()
    }

    /** Remembers [store] and applies it to every current and future [PluginSettingsAware] backend. */
    @Synchronized
    fun setPluginSettings(store: PluginSettingsStore) {
        pluginSettings = store
        applyPluginSettings()
    }

    @Synchronized
    fun reload() {
        backends.clear()
        availabilityCache.clear()

        // Built-ins (same extension JAR). Pass the extension's classloader explicitly — Burp loads
        // each extension under its own classloader, so the default `Thread.currentThread()
        // .contextClassLoader` may not see this JAR's META-INF/services and ServiceLoader would
        // silently return an empty list, falling back to the hardcoded list below. Using the class
        // own loader resolves all registered factories reliably.
        val builtIns =
            ServiceLoader
                .load(AiBackendFactory::class.java, AiBackendFactory::class.java.classLoader)
                .toList()
        if (builtIns.isEmpty()) {
            api.logging().logToOutput("No AiBackendFactory found via ServiceLoader; falling back to built-ins.")
            // Core's HTTP backends only. Phase 29 / D-03: the full build's CLI backends register through
            // src/full's services file and are never named here, so the store build cannot reach them.
            listOf(
                LmStudioBackendFactory(),
                OllamaBackendFactory(),
                NvidiaNimBackendFactory(),
                OpenAiCompatibleBackendFactory(),
                PerplexityBackendFactory(),
                AnthropicBackendFactory(),
            ).forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
        } else {
            builtIns.forEach { f ->
                val b = f.create()
                backends[b.id] = b
            }
        }

        // Burp AI backend (requires MontoyaApi, registered directly)
        try {
            val burpAi = BurpAiBackend(api)
            backends[burpAi.id] = burpAi
        } catch (e: Exception) {
            api.logging().logToOutput("Burp AI backend not available: ${e.message}")
        }

        // Phase 31 / D-14: backends from outside the extension JAR, after the built-ins and Burp AI as in
        // 1.0.1. Each source first releases what its previous load opened, so repeated Settings saves do
        // not leak class loaders. None is registered in the store build.
        externalSources.forEach { source ->
            guardedSource(source) {
                source.close()
                source
                    .load(
                        parent = this::class.java.classLoader,
                        log = { api.logging().logToOutput(it) },
                        logError = { api.logging().logToError(it) },
                    ).forEach { b -> backends[b.id] = b }
            }
        }

        applyHttpTransport()
        applyPluginSettings()

        // Phase 29 / D-09: each backend publishes its own token ratio; core names no full-only id.
        backends.values.forEach { backend ->
            backend.charsPerTokenEstimate?.let { TokenTracker.registerCharsPerToken(backend.id, it) }
        }

        api.logging().logToOutput("Total backends registered: ${backends.size}")
    }

    fun get(id: String): AiBackend? = backends[id]

    fun isRegistered(backendId: String): Boolean = backends.containsKey(backendId)

    /**
     * [backendId] when this build registers it, otherwise [DEFAULT_BACKEND_ID]. Phase 29 / D-08: a
     * saved id the build does not have (a CLI id a full install left behind, in the store build) falls
     * back to Burp AI. Callers never persist the substitute, so switching back restores the choice.
     */
    fun resolve(backendId: String): String = if (isRegistered(backendId)) backendId else DEFAULT_BACKEND_ID

    companion object {
        const val DEFAULT_BACKEND_ID = AgentSettingsRepository.DEFAULT_PREFERRED_BACKEND_ID
    }

    fun listBackendIds(settings: com.six2dez.burp.aiagent.config.AgentSettings): List<String> {
        val settingsHash = settings.hashCode()
        return backends.values
            .filter { backend ->
                val cacheKey = Pair(backend.id, settingsHash)
                availabilityCache.getOrPut(cacheKey) { backend.isAvailable(settings) }
            }.sortedBy { it.displayName }
            .map { it.id }
    }

    /** Returns all registered backend IDs regardless of availability. */
    fun listAllBackendIds(): List<String> =
        backends.values
            .sortedBy { it.displayName }
            .map { it.id }

    fun healthCheck(
        backendId: String,
        settings: AgentSettings,
    ): HealthCheckResult {
        val backend =
            backends[backendId]
                ?: return HealthCheckResult.Unavailable("Backend not found: $backendId")
        return try {
            val result = backend.healthCheck(settings)
            if (result is HealthCheckResult.Unknown) unknownHealth(backend, settings) else result
        } catch (e: Exception) {
            // An AiAccessRefusedException from the egress gate lands here as Unavailable(refusal).
            HealthCheckResult.Unavailable(e.message ?: "Health check failed")
        }
    }

    /**
     * Maps a backend's `Unknown` health (it sent no request, e.g. Anthropic) to a result. Phase 31 /
     * GATE-01 (Pitfall 4): the egress gate is asked first, so a backend the gate refuses never reads
     * "Connection OK."; with no transport ever set, the check cannot be trusted and reports Unavailable.
     */
    private fun unknownHealth(
        backend: AiBackend,
        settings: AgentSettings,
    ): HealthCheckResult {
        val transport =
            httpTransport
                ?: return HealthCheckResult.Unavailable("MontoyaHttpTransport unavailable; health checks require Burp's HTTP stack.")
        transport.forBackend(backend.id).requireEgress()
        return if (backend.isAvailable(settings)) {
            HealthCheckResult.Healthy
        } else {
            HealthCheckResult.Unavailable("Backend is not available with current configuration.")
        }
    }

    /**
     * Extension unload. Each backend releases its process-wide resources first (the full build's CLI
     * backends drain their temp-file registry and unregister its JVM exit hook here). REL-07 / SC5 /
     * D-03: this runs after the supervisor has stopped, so every in-flight CLI call has already run its
     * finally block and the drain sweeps a settled set. It is also the ONLY cleanup an unload gets: the
     * JVM exit hook does not fire when the extension is unloaded while Burp keeps running. Unregistering
     * the hook here is what stops a reload from pinning a dead classloader (threat T-24-07).
     * Never called from [reload]: a Settings save must not drain files of calls still in flight.
     */
    fun shutdown() {
        backends.values.forEach { backend ->
            try {
                backend.shutdown()
            } catch (e: Exception) {
                api.logging().logToError("Backend ${backend.id} shutdown failed: ${e.message}")
            }
        }
        backends.clear()
        availabilityCache.clear()
        externalSources.forEach { source -> guardedSource(source) { source.close() } }
    }

    private fun applyHttpTransport() {
        val transport = httpTransport ?: return
        backends.values.forEach { backend ->
            if (backend is HttpTransportAware) {
                backend.setHealthCheckTransport(transport.forBackend(backend.id))
            }
        }
    }

    private fun applyPluginSettings() {
        val store = pluginSettings ?: return
        backends.values.forEach { backend ->
            if (backend is PluginSettingsAware) {
                backend.setPluginSettings(store)
            }
        }
    }

    // TooGenericExceptionCaught: an external source is plug-in code and may throw anything; one broken
    // source must not abort a reload or an unload, and the built-in backends stay registered.
    @Suppress("TooGenericExceptionCaught")
    private fun guardedSource(
        source: ExternalBackendSource,
        action: () -> Unit,
    ) {
        try {
            action()
        } catch (e: Exception) {
            api.logging().logToError("External backend source ${source.javaClass.name} failed: ${e.message}")
        }
    }
}
