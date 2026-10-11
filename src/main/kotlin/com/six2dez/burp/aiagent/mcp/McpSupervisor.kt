package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.ToolRegistry
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.ToolProvider
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import java.net.BindException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

interface McpTakeoverClient {
    fun probe(settings: McpSettings): Boolean

    fun requestShutdown(settings: McpSettings): Boolean
}

class McpSupervisor(
    private val api: MontoyaApi,
    private val serverManager: McpServerManager = KtorMcpServerManager(api),
    private val stdioBridge: McpStdioBridge = McpStdioBridge(api),
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(),
    private val takeoverClientOverride: McpTakeoverClient? = null,
    private val maxRestartAttempts: Int = DEFAULT_MAX_RESTART_ATTEMPTS,
    private val maxTakeoverAttempts: Int = DEFAULT_MAX_TAKEOVER_ATTEMPTS,
    private val restartDelayMs: Long = DEFAULT_RESTART_DELAY_MS,
    private val takeoverRetryDelayMs: Long = DEFAULT_TAKEOVER_RETRY_DELAY_MS,
) {
    /** The providers whose lifecycle hooks run on apply and stop. A test seam; production uses the catalog's registry. */
    internal var toolRegistry: () -> ToolRegistry = { McpToolCatalog.registry }
    private val pluginSettingsRef = AtomicReference<PluginSettingsStore?>(null)
    private val stateRef = AtomicReference<McpServerState>(McpServerState.Stopped)
    private val settingsRef = AtomicReference<McpSettings?>(null)
    private val privacyRef = AtomicReference(PrivacyMode.STRICT)
    private val determinismRef = AtomicReference(false)
    private val preprocessRef = AtomicReference(ResponsePreprocessorSettings())
    private val restartAttempts = AtomicInteger(0)
    private val takeoverAttempts = AtomicInteger(0)
    private val takeoverClient: McpTakeoverClient =
        takeoverClientOverride ?: object : McpTakeoverClient {
            override fun probe(settings: McpSettings): Boolean = probeExistingServer(settings)

            override fun requestShutdown(settings: McpSettings): Boolean = requestRemoteShutdown(settings)
        }

    init {
        require(maxRestartAttempts >= 0) { "maxRestartAttempts must be >= 0" }
        require(maxTakeoverAttempts >= 0) { "maxTakeoverAttempts must be >= 0" }
        require(restartDelayMs > 0) { "restartDelayMs must be > 0" }
        require(takeoverRetryDelayMs > 0) { "takeoverRetryDelayMs must be > 0" }
    }

    fun setAiRequestLogger(logger: AiRequestLogger) {
        serverManager.setAiRequestLogger(logger)
        stdioBridge.setAiRequestLogger(logger)
    }

    fun setPluginSettings(store: PluginSettingsStore) {
        pluginSettingsRef.set(store)
    }

    fun setAiToolDependencies(
        supervisor: AgentSupervisor,
        passiveScanner: PassiveAiScanner,
        backendRegistry: BackendRegistry,
    ) {
        serverManager.setAiToolDependencies(supervisor, passiveScanner, backendRegistry)
    }

    fun applySettings(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings,
    ) {
        val previousSettings = settingsRef.get()
        val previousPrivacy = privacyRef.get()
        val previousDeterminism = determinismRef.get()
        val previousPreprocess = preprocessRef.get()

        settingsRef.set(settings)
        privacyRef.set(privacyMode)
        determinismRef.set(determinismMode)
        preprocessRef.set(preprocessSettings)
        notifySettingsApplied(settings)

        if (!settings.enabled) {
            stop()
            return
        }

        val alreadyRunning = stateRef.get() is McpServerState.Running
        val settingsUnchanged =
            previousSettings == settings &&
                previousPrivacy == privacyMode &&
                previousDeterminism == determinismMode &&
                previousPreprocess == preprocessSettings
        if (alreadyRunning && settingsUnchanged) {
            if (settings.stdioEnabled) {
                stdioBridge.start(settings, privacyMode, determinismMode, preprocessSettings)
            } else {
                stdioBridge.stop()
            }
            return
        }

        restartAttempts.set(0)
        takeoverAttempts.set(0)
        startInternal(settings, privacyMode, determinismMode, preprocessSettings)

        if (settings.stdioEnabled) {
            stdioBridge.start(settings, privacyMode, determinismMode, preprocessSettings)
        } else {
            stdioBridge.stop()
        }
    }

    fun status(): McpServerState = stateRef.get()

    fun stop() {
        serverManager.stop { state ->
            stateRef.set(state)
        }
        restartAttempts.set(0)
        takeoverAttempts.set(0)
        stdioBridge.stop()
        toolRegistry().providers().forEach { provider ->
            runProviderHook(provider, "onMcpServerStopped") { provider.onMcpServerStopped() }
        }
    }

    /**
     * Phase 29 / D-15 — the core names no plug-in state: each provider configures what it owns (the
     * generic provider: the scanner-task and Collaborator registries and their TTLs) from its own keys.
     * Skipped until [setPluginSettings] supplied the store; App sets it before the first apply.
     */
    private fun notifySettingsApplied(settings: McpSettings) {
        val store = pluginSettingsRef.get() ?: return
        val log: (String) -> Unit = { api.logging().logToOutput(it) }
        toolRegistry().providers().forEach { provider ->
            runProviderHook(provider, "onMcpSettingsApplied") { provider.onMcpSettingsApplied(settings, store, log) }
        }
    }

    /** A provider hook that throws is logged and skipped, so one plug-in cannot stop the others or the server. */
    @Suppress("TooGenericExceptionCaught") // any plug-in failure, whatever its type, must stay contained here
    private fun runProviderHook(
        provider: ToolProvider,
        hook: String,
        block: () -> Unit,
    ) {
        try {
            block()
        } catch (e: Exception) {
            api.logging().logToError("MCP tool provider ${provider.javaClass.name} failed in $hook: ${e.message}")
        }
    }

    fun shutdown() {
        scheduler.shutdown()
        try {
            scheduler.awaitTermination(5, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        serverManager.shutdown()
        stdioBridge.stop()
    }

    private fun startInternal(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings,
    ) {
        serverManager.start(settings, privacyMode, determinismMode, preprocessSettings) { state ->
            stateRef.set(state)
            if (state is McpServerState.Running) {
                restartAttempts.set(0)
                takeoverAttempts.set(0)
            }
            if (state is McpServerState.Failed) {
                handleFailure(state.exception)
            }
        }
    }

    private fun handleFailure(exception: Throwable) {
        val settings = settingsRef.get() ?: return
        if (!settings.enabled) return

        if (isBindException(exception)) {
            handleBindFailure(settings)
            return
        }

        val attempt = restartAttempts.incrementAndGet()
        if (attempt > maxRestartAttempts) {
            api.logging().logToError("MCP server failed repeatedly. Giving up after $attempt attempts: ${exception.message}")
            return
        }

        api.logging().logToError("MCP server failed. Restarting in ${restartDelayMs}ms (attempt $attempt/$maxRestartAttempts).")
        scheduleStart(restartDelayMs)
    }

    private fun handleBindFailure(settings: McpSettings) {
        when (attemptTakeover(settings)) {
            BindTakeoverOutcome.SHUTDOWN_REQUESTED -> {
                val attempt = takeoverAttempts.incrementAndGet()
                if (attempt > maxTakeoverAttempts) {
                    api.logging().logToError(
                        "MCP bind conflict persists after $attempt takeover attempts. " +
                            "Port ${settings.host}:${settings.port} is still unavailable.",
                    )
                    return
                }
                api.logging().logToOutput(
                    "MCP bind conflict detected on ${settings.host}:${settings.port}. " +
                        "Shutdown requested from existing MCP server; retrying in ${takeoverRetryDelayMs}ms " +
                        "(attempt $attempt/$maxTakeoverAttempts).",
                )
                scheduleStart(takeoverRetryDelayMs)
            }

            BindTakeoverOutcome.NO_COMPATIBLE_SERVER -> {
                api.logging().logToError(
                    "MCP server failed to bind on ${settings.host}:${settings.port}. " +
                        "Port appears busy and no compatible MCP server was detected for takeover.",
                )
            }

            BindTakeoverOutcome.SHUTDOWN_REJECTED -> {
                api.logging().logToError(
                    "MCP bind conflict on ${settings.host}:${settings.port}. " +
                        "Existing MCP server did not accept shutdown request.",
                )
            }
        }
    }

    private fun attemptTakeover(settings: McpSettings): BindTakeoverOutcome {
        if (!takeoverClient.probe(settings)) {
            return BindTakeoverOutcome.NO_COMPATIBLE_SERVER
        }
        return if (takeoverClient.requestShutdown(settings)) {
            BindTakeoverOutcome.SHUTDOWN_REQUESTED
        } else {
            BindTakeoverOutcome.SHUTDOWN_REJECTED
        }
    }

    private fun scheduleStart(delayMs: Long) {
        scheduler.schedule({
            val current = settingsRef.get() ?: return@schedule
            if (!current.enabled) return@schedule
            startInternal(current, privacyRef.get(), determinismRef.get(), preprocessRef.get())
        }, delayMs, TimeUnit.MILLISECONDS)
    }

    private fun isBindException(exception: Throwable): Boolean {
        var current: Throwable? = exception
        while (current != null) {
            if (current is BindException) return true
            current = current.cause
        }
        return false
    }

    private fun probeExistingServer(settings: McpSettings): Boolean =
        try {
            val scheme = if (settings.tlsEnabled) "https" else "http"
            val url = URI.create("$scheme://${settings.host}:${settings.port}/__mcp/health").toURL()
            val conn = openConnection(url, settings)
            try {
                conn.requestMethod = "GET"
                conn.connectTimeout = 800
                conn.readTimeout = 800
                conn.connect()
                val alive = conn.responseCode in 200..299
                // SEC-04 / D-02 / D-05: the identity assertion below is mode-aware because the server
                // side is. Three facts, all load-bearing:
                // (1) KtorMcpServerManager appends `X-Burp-AI-Agent: mcp` to /__mcp/health ONLY when
                //     external access is disabled. Requiring it unconditionally would make
                //     attemptTakeover return NO_COMPATIBLE_SERVER on every external-mode bind
                //     conflict, and handleBindFailure would then schedule NO retry at all — the MCP
                //     server would stay down silently.
                // (2) The header was always trivially spoofable by whichever process holds the port,
                //     which is exactly Finding 7. Degrading external takeover to a liveness check
                //     therefore takes away no guarantee that previously held.
                // (3) Establishing REAL listener identity is Phase 25 / SEC-07 per D-05. Nothing in
                //     this probe may present the bearer token to an unverified port holder, so it
                //     sends no credential header of any kind — do not add one here.
                // (4) SEC-07 update: the signals inspected below are no longer load-bearing for
                //     credential disclosure, because the takeover path no longer has a secret to
                //     disclose — requestRemoteShutdown presents a proof of possession instead of the
                //     token. They remain as a cheap filter that avoids issuing shutdown requests at
                //     listeners that are obviously not ours.
                if (alive && settings.externalEnabled) {
                    api.logging().logToOutput(
                        "MCP probe on ${settings.host}:${settings.port} could not establish server identity: " +
                            "the identifying header is emitted in local mode only. " +
                            "Proceeding with takeover on liveness alone.",
                    )
                }
                alive && (settings.externalEnabled || conn.getHeaderField("X-Burp-AI-Agent") == "mcp")
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            api.logging().logToOutput("MCP probe failed on ${settings.host}:${settings.port}: ${e.message}")
            false
        }

    /**
     * SEC-07 / T-25-01 — the Phase-22-era name was `requestRemoteShutdownWithToken`, and it stopped
     * being true here: the MCP bearer token is no longer sent to the port holder. It keys an HMAC that
     * proves possession instead, so a local process squatting the port collects nothing it can reuse.
     *
     * Fails closed on a blank token: without a key there is no meaningful proof, and the old code
     * would have presented a bare `Bearer ` to the holder. No request is issued at all in that case.
     */
    private fun requestRemoteShutdown(settings: McpSettings): Boolean {
        val proof = takeoverProof(settings) ?: return false
        return try {
            val scheme = if (settings.tlsEnabled) "https" else "http"
            val url = URI.create("$scheme://${settings.host}:${settings.port}/__mcp/shutdown").toURL()
            val conn = openConnection(url, settings)
            try {
                conn.requestMethod = "POST"
                conn.setRequestProperty(McpTakeoverProof.HEADER, proof)
                conn.connectTimeout = 500
                conn.readTimeout = 500
                conn.connect()
                conn.responseCode in 200..299
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            api.logging().logToOutput("MCP remote shutdown request was not accepted: ${e.message}")
            false
        }
    }

    /**
     * The ONLY place in this file that touches the MCP token, and it uses it as an HMAC key rather
     * than as a header value. `McpTakeoverSquatterTest` asserts that structurally: the token property
     * is referenced exactly once in this file, on a line that also carries
     * `McpTakeoverProof.forTarget`. That assertion goes red the day a future edit puts the secret back
     * on the wire under any header name — so do not name that property anywhere else here, not even
     * in a comment.
     */
    private fun takeoverProof(settings: McpSettings): String? = settings.token.takeIf { it.isNotBlank() }?.let { McpTakeoverProof.forTarget(it, settings.host, settings.port, System.currentTimeMillis()) }

    /**
     * SEC-07 / SC5 / T-25-12 — the loopback TLS branch used to install a trust manager whose
     * `checkServerTrusted` body was `= Unit` together with a hostname verifier that returned true
     * unconditionally, so the takeover client could not tell this extension's own MCP server from any
     * local process holding the port with any self-signed certificate. Both are gone. The client now
     * trusts exactly one certificate: the leaf in the keystore that `settings.tlsKeystorePath` names,
     * which is the same file `KtorMcpServerManager.start` hands to Ktor's `sslConnector`.
     *
     * The hostname verifier is REPLACED rather than disabled. `McpTls` generates the certificate with
     * `-dname CN=burp-mcp`, which can never match `localhost` or `127.0.0.1`, so name-based identity
     * was never available here; the identity assertion moves from the name to the key.
     *
     * Fails closed when no pin can be read: no TLS override is installed at all, the JDK defaults
     * reject the self-signed certificate and the takeover does not happen. That is a classification,
     * not a degradation — `KtorMcpServerManager.start` throws
     * `IllegalStateException("TLS enabled but keystore not available.")` when `McpTls.resolve` returns
     * null, so our own server cannot be running under TLS unless a readable keystore exists at that
     * path. A client that cannot read one there is not talking to our server, and weakening TLS to
     * reach it would be exactly backwards. See ADR-16.
     *
     * The pin is scoped to a LOOPBACK bind, and a non-loopback bind is an explicit limb rather than a
     * silent fall-through (25-REVIEW WR-03). External mode is the only mode that permits a
     * non-loopback host, and there no override is installed, the JDK defaults refuse our own
     * `CN=burp-mcp` certificate and the takeover does not happen — so the operator is told that,
     * rather than being told by `handleBindFailure` that no compatible MCP server was found when the
     * listener was their own. Dropping the host gate, which would make external-mode TLS takeover work
     * for the first time, is an accepted residual recorded in ADR-17; it is a change to when this
     * extension shuts down a remote listener and belongs to a hardening phase, not to this one.
     */
    private fun openConnection(
        url: URL,
        settings: McpSettings,
    ): HttpURLConnection {
        val conn = url.openConnection() as HttpURLConnection
        if (settings.tlsEnabled && conn is HttpsURLConnection) {
            if (isLoopbackUrlHost(url.host)) {
                installLoopbackPin(conn, settings)
            } else {
                // 25-REVIEW WR-03. This limb used to be a silent fall-through: nothing was installed,
                // the JDK default trust store refused our own CN=burp-mcp certificate,
                // probeExistingServer returned false and handleBindFailure reported "no compatible
                // MCP server was detected" — the opposite of what happened, with no retry scheduled.
                // The gate itself is unchanged; only the operator's information is.
                api.logging().logToOutput(
                    "MCP takeover was not attempted under TLS: certificate pinning is applied to " +
                        "loopback hosts only and this server is bound to ${url.host}. No TLS override " +
                        "was installed and the existing listener was left running — free the port " +
                        "manually, then restart MCP.",
                )
            }
        }
        return conn
    }

    /**
     * The loopback limbs of [openConnection]'s TLS branch, unchanged in behaviour: pin when a
     * certificate can be read, and fail closed with one Output line naming the keystore path when it
     * cannot. Extracted only so the non-loopback limb above reads as its own case rather than as the
     * absence of one.
     */
    private fun installLoopbackPin(
        conn: HttpsURLConnection,
        settings: McpSettings,
    ) {
        val pin = McpTls.pinnedLeafSha256(settings)
        if (pin == null) {
            api.logging().logToOutput(
                "MCP takeover was not attempted under TLS: no pinned certificate could be read from " +
                    "${settings.tlsKeystorePath}. The takeover client trusts only the certificate in " +
                    "that keystore and never falls back to trusting an unidentified listener.",
            )
        } else {
            conn.sslSocketFactory = pinnedSslContext(pin).socketFactory
            conn.hostnameVerifier =
                HostnameVerifier { _, session ->
                    // An unverified session must yield false rather than propagate
                    // SSLPeerUnverifiedException out of the verifier.
                    leafDigestMatches(runCatching { session.peerCertificates }.getOrNull(), pin)
                }
        }
    }

    private fun isLoopbackUrlHost(host: String): Boolean =
        host.equals("localhost", ignoreCase = true) ||
            host == "127.0.0.1" ||
            host == "::1"

    /**
     * An [SSLContext] whose only trust manager accepts a chain if and only if its leaf certificate
     * digests to [pin].
     */
    private fun pinnedSslContext(pin: ByteArray): SSLContext {
        val pinned =
            arrayOf<TrustManager>(
                object : X509TrustManager {
                    override fun getAcceptedIssuers() = emptyArray<X509Certificate>()

                    // Client-side manager: this is never called. It throws rather than returning Unit
                    // so that reusing this object on a server would fail loudly instead of trusting
                    // every client that ever connects.
                    override fun checkClientTrusted(
                        chain: Array<X509Certificate>,
                        authType: String,
                    ): Unit = throw CertificateException("This trust manager is client-side only and authenticates no clients.")

                    override fun checkServerTrusted(
                        chain: Array<X509Certificate>,
                        authType: String,
                    ) {
                        if (!leafDigestMatches(chain, pin)) {
                            throw CertificateException(
                                "The listener on the MCP port presented a certificate that does not match the " +
                                    "one in the configured keystore. Refusing the takeover.",
                            )
                        }
                    }
                },
            )
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, pinned, SecureRandom())
        return sslContext
    }

    /** True when the first certificate of [chain] digests to [pin]. Compared with `MessageDigest.isEqual`. */
    private fun leafDigestMatches(
        chain: Array<out Certificate>?,
        pin: ByteArray,
    ): Boolean {
        val digest =
            chain?.firstOrNull()?.let { leaf ->
                runCatching { MessageDigest.getInstance("SHA-256").digest(leaf.encoded) }.getOrNull()
            }
        return digest != null && MessageDigest.isEqual(digest, pin)
    }

    private enum class BindTakeoverOutcome {
        SHUTDOWN_REQUESTED,
        NO_COMPATIBLE_SERVER,
        SHUTDOWN_REJECTED,
    }

    private companion object {
        private const val DEFAULT_MAX_RESTART_ATTEMPTS = 4
        private const val DEFAULT_MAX_TAKEOVER_ATTEMPTS = 3
        private const val DEFAULT_RESTART_DELAY_MS = 2_000L
        private const val DEFAULT_TAKEOVER_RETRY_DELAY_MS = 1_000L
    }
}
