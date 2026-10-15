package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.scancheck.ScanCheckType
import burp.api.montoya.ui.contextmenu.AuditIssueContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.RollingLogConfig
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.toPreprocessorSettings
import com.six2dez.burp.aiagent.context.ContextCollector
import com.six2dez.burp.aiagent.mcp.McpCoroutines
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.SafeRegex
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.AiPassiveScanCheck
import com.six2dez.burp.aiagent.scanner.AiScanCheck
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.PluginHost
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.MainTab
import com.six2dez.burp.aiagent.ui.UiActions
import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import java.nio.file.Paths
import java.util.ServiceConfigurationError
import java.util.concurrent.atomic.AtomicBoolean

object App {
    lateinit var api: MontoyaApi
        private set

    lateinit var backendRegistry: BackendRegistry
        private set
    lateinit var auditLogger: AuditLogger
        private set
    lateinit var supervisor: AgentSupervisor
        private set
    lateinit var mcpSupervisor: McpSupervisor
        private set
    lateinit var contextCollector: ContextCollector
        private set
    lateinit var passiveAiScanner: PassiveAiScanner
        private set
    lateinit var activeAiScanner: ActiveAiScanner
        private set
    private var mainTab: MainTab? = null
    lateinit var aiRequestLogger: AiRequestLogger
        private set

    private lateinit var settingsRepo: AgentSettingsRepository

    @Volatile
    private var installedPlugins: List<ExtensionPlugin> = emptyList()

    /** D-07: set by the first [shutdown] of a load, so a second call (handler after failed-load cleanup) is a no-op. */
    private val shutdownStarted = AtomicBoolean(false)

    fun initialize(montoyaApi: MontoyaApi) {
        // A new load: the next shutdown must run again.
        shutdownStarted.set(false)
        api = montoyaApi
        // UI-SPEC PC-15: the profile is resolved ONCE. The banner and the Help caption both come from it,
        // so a provider conflict is logged once and the two can never disagree.
        val flavorProfile =
            resolveFlavorProfile { providers ->
                api.logging().logToError(
                    "More than one FlavorProfile provider found (${providers.joinToString(", ")}); " +
                        "using the BApp Store default.",
                )
            }
        registerExtensionIdentity(api, flavorProfile)

        BackendDiagnostics.output = { api.logging().logToOutput(it) }
        BackendDiagnostics.error = { api.logging().logToError(it) }
        // (PRIV-06) D-03: surface a redaction truncation to the user in the Output tab. It belongs
        // here with the other diagnostics sinks rather than at the Redaction.setCustomPatterns
        // seeding below, because this sink is set once and never changes. The notice itself is
        // rate-limited inside Redaction and carries counts only, never dropped content.
        Redaction.truncationLogger = { api.logging().logToOutput(it) }
        api.logging().logToOutput("Backend diagnostics enabled.")

        settingsRepo = AgentSettingsRepository(api)
        backendRegistry = BackendRegistry(api)
        // Phase 29 / D-06: backends whose settings live in plug-in keys read them through this store.
        backendRegistry.setPluginSettings(settingsRepo.pluginSettings())
        auditLogger = AuditLogger(api)
        AuditLogger.registerGlobalEmitter { type, payload -> auditLogger.logEvent(type, payload) }
        val aiAccessPolicy =
            resolveAiAccessPolicy { providers ->
                api.logging().logToError(
                    "More than one AiAccessPolicy provider found (${providers.joinToString(", ")}); " +
                        "the strict BApp Store AI access policy is in force.",
                )
            }
        supervisor = AgentSupervisor(api, backendRegistry, auditLogger, aiAccessPolicy)
        // Phase 31 / D-15: one Output line per load with the edition and the isEnabled() result or throw.
        api.logging().logToOutput(burpAiLoadDiagnostics(api))
        mirrorAppliedSettingsInto(settingsRepo, supervisor)
        supervisor.pluginSettings = settingsRepo.pluginSettings()
        aiRequestLogger = AiRequestLogger()
        supervisor.aiRequestLogger = aiRequestLogger
        mcpSupervisor = McpSupervisor(api)
        mcpSupervisor.setAiRequestLogger(aiRequestLogger)
        mcpSupervisor.setPluginSettings(settingsRepo.pluginSettings())
        contextCollector = ContextCollector(api)
        passiveAiScanner = PassiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        passiveAiScanner.aiRequestLogger = aiRequestLogger
        activeAiScanner = ActiveAiScanner(api, supervisor, auditLogger) { settingsRepo.load() }
        mcpSupervisor.setAiToolDependencies(supervisor, passiveAiScanner, backendRegistry)

        AgentProfileLoader.ensureBundledProfilesInstalled()
        val settings = settingsRepo.load()
        // PRIV-02 / CR-01: seed the redaction engine with persisted custom patterns so they are
        // active immediately on launch — NOT only after the user re-saves Settings. Without this,
        // compiledCustomPatterns resets to empty on every Burp restart and the secrets the user
        // configured the tool to strip would be sent to the AI backend until the next manual Save.
        // That rationale is unchanged and load-bearing: seeding still happens, unconditionally.
        //
        // WR-07 / T-21-64 — WHAT CHANGED IS THE TRUST. This call used to be justified with
        // "persisted patterns were already validated by isPatternSafe on save", which is exactly the
        // assumption WR-07 falsifies. Burp preferences are a user-editable store: an entry can be
        // hand-edited, can predate isPatternSafe existing at all, and — now that the probe corpus is
        // a thing that GROWS (it went from one probe to six in this phase) — can predate the corpus
        // that would reject it. Since D-05 a custom pattern runs in EVERY privacy mode including OFF
        // and bodyStage fails CLOSED, so one accepted-but-pathological persisted entry burns
        // MAX_REDACTION_BUDGET_MS and drops real content behind markers on every call. Re-validating
        // here is what stops a stale preferences file from doing that.
        //
        // COST: at most patterns x 6 x SafeRegex.PROBE_ACCESS_BUDGET character accesses once per
        // launch. A pathological pattern is rejected in about 8-15 ms; a realistic ten-pattern list
        // measured 2.2 ms. This runs on the extension-load thread, NOT on the
        // EDT-critical path — the EDT exposure is the save path, tracked for Phase 23 / REL-05.
        //
        // setCustomPatterns still silently drops uncompilable entries; this filter is about
        // pathological-but-compilable ones, which it cannot see.
        Redaction.setCustomPatterns(settings.customRedactionPatterns.filter { SafeRegex.isPatternSafe(it) })
        AgentProfileLoader.setActiveProfile(settings.agentProfile)
        aiRequestLogger.enabled = settings.aiRequestLoggerEnabled
        aiRequestLogger.maxEntries = settings.aiRequestLoggerMaxEntries
        configureRollingLoggerFromProperties()
        BackendDiagnostics.retry = { event ->
            aiRequestLogger.log(
                type = ActivityType.RETRY,
                source = "backend",
                backendId = event.backendId,
                detail = "Retry attempt ${event.attempt} in ${event.delayMs}ms: ${event.reason ?: "unknown"}",
                durationMs = event.delayMs,
                metadata =
                    mapOf(
                        "attempt" to event.attempt.toString(),
                        "delayMs" to event.delayMs.toString(),
                        "reason" to (event.reason ?: ""),
                    ),
            )
        }
        auditLogger.setEnabled(settings.auditEnabled)
        auditLogger.verbose = settings.auditVerbose
        supervisor.applySettings(settings)
        mcpSupervisor.applySettings(
            settings.mcpSettings,
            settings.privacyMode,
            settings.determinismMode,
            settings.toPreprocessorSettings(),
        )

        // Initialize passive AI scanner
        passiveAiScanner.rateLimitSeconds = settings.passiveAiRateSeconds
        passiveAiScanner.scopeOnly = settings.passiveAiScopeOnly
        passiveAiScanner.maxSizeKb = settings.passiveAiMaxSizeKb
        passiveAiScanner.applyOptimizationSettings(settings)
        passiveAiScanner.setEnabled(settings.passiveAiEnabled)

        // Initialize active AI scanner
        activeAiScanner.maxConcurrent = settings.activeAiMaxConcurrent
        activeAiScanner.maxPayloadsPerPoint = settings.activeAiMaxPayloadsPerPoint
        activeAiScanner.timeoutSeconds = settings.activeAiTimeoutSeconds
        activeAiScanner.requestDelayMs = settings.activeAiRequestDelayMs.toLong()
        activeAiScanner.maxRiskLevel = settings.activeAiMaxRiskLevel
        activeAiScanner.scopeOnly = settings.activeAiScopeOnly
        activeAiScanner.scanMode = settings.activeAiScanMode
        activeAiScanner.useCollaborator = settings.activeAiUseCollaborator
        activeAiScanner.setEnabled(settings.activeAiEnabled)

        // Phase 29 / D-02, BUILD-04: full-build plug-ins (the opt-in passive-to-active auto-queue)
        // install here, after both scanners exist. The store JAR has no ExtensionPlugin services file,
        // so it installs nothing and the passive scanner keeps no sink.
        installExtensionPlugins()

        val ui =
            MainTab(
                api,
                settingsRepo,
                backendRegistry,
                supervisor,
                auditLogger,
                mcpSupervisor,
                passiveAiScanner,
                activeAiScanner,
                aiRequestLogger,
                buildIdentity = buildIdentityLine(flavorProfile),
            )
        mainTab = ui
        api.userInterface().registerSuiteTab(EXTENSION_NAME, ui.root)

        // Context menu: requests/responses (all editions)
        api.userInterface().registerContextMenuItemsProvider(
            object : ContextMenuItemsProvider {
                override fun provideMenuItems(event: ContextMenuEvent) =
                    UiActions.requestResponseMenuItems(
                        api,
                        event,
                        ui,
                        mcpSupervisor,
                        passiveAiScanner,
                        activeAiScanner,
                        auditLogger,
                    )

                // Scanner findings (Pro): use the dedicated event type
                override fun provideMenuItems(event: AuditIssueContextMenuEvent) = UiActions.auditIssueMenuItems(api, event, ui, mcpSupervisor)
            },
        )

        // Prime the BountyPrompt definition cache off-thread so the first right-click doesn't parse
        // the prompt directory on the EDT (BApp #231, finding 2).
        UiActions.refreshBountyPromptCache(settings)

        // Register AI ScanCheck with Burp Scanner (Burp Pro only - Option A)
        // This integrates with Burp's native active scanner
        try {
            val aiScanCheck = AiScanCheck(api) { settingsRepo.load() }
            api.scanner().registerActiveScanCheck(aiScanCheck, ScanCheckType.PER_INSERTION_POINT)
            api.logging().logToOutput("AI ScanCheck registered with Burp Scanner (Pro feature)")
        } catch (e: Exception) {
            // Expected to fail on Community edition
            api.logging().logToOutput("AI ScanCheck not registered (Burp Pro required): ${e.message}")
        }

        // Register AI PassiveScanCheck with Burp Scanner (Burp Pro only)
        // Uses the modern PassiveScanCheck interface (BApp Store requirement)
        // Community edition: registerPassiveScanCheck throws → caught → extension continues normally
        try {
            val aiPassiveScanCheck = AiPassiveScanCheck(api, passiveAiScanner) { settingsRepo.load() }
            api.scanner().registerPassiveScanCheck(aiPassiveScanCheck, ScanCheckType.PER_REQUEST)
            api.logging().logToOutput("AI PassiveScanCheck registered with Burp Scanner (Pro feature)")
        } catch (e: Exception) {
            // Expected to fail on Community edition
            api.logging().logToOutput("AI PassiveScanCheck not registered (Burp Pro required): ${e.message}")
        }

        api.logging().logToOutput(
            "AI Agent extension loaded. Backends discovered: ${backendRegistry.listBackendIds(settingsRepo.load()).joinToString(", ")}",
        )
        api.logging().logToOutput(
            "Privacy mode: ${settings.privacyMode.name}. " +
                "Change it in Settings > Privacy. Context captured from menus is previewed before being sent to the AI.",
        )
    }

    /**
     * Phase 33 — unloads the extension: inbound first, within one shared [deadline], silent when clean.
     *
     * **Order (D-06).** Work that arrives from outside stops before the objects it uses are torn down:
     * 0. MainTab quiesce: no settings write (which could restart MCP or a scanner) can start any more;
     *    timers that trigger work stop. No waits.
     * 1. MCP supervisor: latches, drops pending restarts, closes the port, stops the stdio bridge and
     *    clears provider state. MCP must stop before the chat supervisor and the backends it calls.
     * 2. Plug-ins, then the passive and the active scanner.
     * 3. Chat supervisor, backend registry, AI request logger.
     * 4. MainTab dispose (Swing on the EDT) and the global sinks.
     * 5. The extension-owned MCP coroutine dispatcher, then the sweep of every pool still tracked.
     * 6. Only when [shutdownSharedCoroutines]: the shared coroutine dispatchers.
     *
     * **Budget (D-05).** Every step shares [deadline] (10 s by default) and waits only for what is left;
     * once it is spent the remaining pools are forced without waiting. Uninterruptible work (a Montoya
     * request in flight) is left to the final sweep, so it costs the budget once.
     *
     * **Reporting (D-09).** A clean unload writes no Error line; a step that timed out or had to be
     * forced writes exactly one line naming its component.
     *
     * **Shared coroutines (D-12).** `Dispatchers.shutdown()` is irreversible for the classloader, so only
     * the production handler in [BurpAiAgentExtension] passes `shutdownSharedCoroutines = true`, and
     * [McpCoroutines.shutdownSharedDispatchers] still does nothing unless kotlinx.coroutines belongs to
     * this extension's own classloader. The default never does it.
     *
     * **Robustness (D-07).** Safe on a partly initialized App: a load that threw part-way leaves some
     * fields unset, and every step skips a component that was never built. Idempotent: only the first
     * call of a load runs; a second call (Burp's handler after the failed-load cleanup) returns at once.
     */
    fun shutdown(
        shutdownSharedCoroutines: Boolean = false,
        deadline: ShutdownDeadline = ShutdownDeadline.unload(),
    ) {
        if (!shutdownStarted.compareAndSet(false, true)) return
        // (0) Quiesce.
        safeShutdownStep("MainTab quiesce") { mainTab?.quiesce() }
        // (1) Inbound: the MCP server and the stdio bridge.
        safeShutdownStep("MCP supervisor", this::mcpSupervisor.isInitialized) { mcpSupervisor.shutdown(deadline) }
        // (2) Plug-ins unhook before the scanners stop (the auto-queue plug-in clears the passive sink).
        installedPlugins.forEach { plugin ->
            safeShutdownStep("Plug-in ${plugin.javaClass.name}") { plugin.shutdown() }
        }
        installedPlugins = emptyList()
        // setEnabled(false) waits for nothing; it clears the shared scan knowledge base, which shutdown does not.
        safeShutdownStep("Passive scanner", this::passiveAiScanner.isInitialized) {
            passiveAiScanner.setEnabled(false)
            passiveAiScanner.shutdown(deadline)
        }
        // shutdown(deadline) disables the scanner itself and always reaches the per-request pool, so a
        // separate disable step can no longer skip it.
        safeShutdownStep("Active scanner", this::activeAiScanner.isInitialized) { activeAiScanner.shutdown(deadline) }
        // (3) The AI side.
        safeShutdownStep("Supervisor", this::supervisor.isInitialized) { supervisor.shutdown() }
        // REL-07 / SC5 / D-03: each backend's shutdown() runs inside this step, after the supervisor has
        // stopped. In the full build that drains the CLI temp-file registry (T-24-07; see
        // BackendRegistry.shutdown()).
        safeShutdownStep("Backend registry", this::backendRegistry.isInitialized) { backendRegistry.shutdown() }
        safeShutdownStep("AI Request Logger", this::aiRequestLogger.isInitialized) { aiRequestLogger.shutdown() }
        // (4) The UI and the global sinks.
        safeShutdownStep("MainTab dispose") { mainTab?.dispose(deadline) }
        mainTab = null
        BackendDiagnostics.retry = null
        safeShutdownStep("Redaction mappings") { Redaction.clearMappings() }
        // (PRIV-06) WR-04 / W-08 / T-21-66: unwire the truncation sink beside clearMappings(), so
        // both pieces of Redaction's global state are released together. The lambda set in
        // initialize() captures `api`, and Redaction is a singleton that outlives this extension
        // instance, so leaving it wired hands a torn-down api.logging() to whatever redaction is
        // still in flight on a Burp scanner thread or an MCP tool thread. Every other global sink
        // here is already unwired — BackendDiagnostics.retry above, AuditLogger's emitter below —
        // and this was the one addition that was set and never cleared.
        //
        // WHAT CHANGED SINCE PLAN 21-12 DEFERRED THIS. The deferral called it a teardown-race
        // robustness issue, accurate at the time: maybeLogTruncation was only reachable from
        // windowedScan's budget-exhaustion branch and dropOrRetry, i.e. oversized bodies. This phase
        // added a third call site inside redactCookieSections, which runs in the HEADER stage of
        // every Redaction.apply where stripCookies is true — the default BALANCED mode, on every MCP
        // tool call and every passive scan, not only on oversized bodies. The window is now reachable
        // far more often than when it was recorded.
        //
        // This step is SOURCE-ASSERTED, not test-asserted: shutdown() needs a live MontoyaApi, so no
        // unit test exercises it. The defence that IS automated is maybeLogTruncation's runCatching
        // (RedactionTest.truncationLoggerThatThrowsDoesNotAbortRedaction), which keeps the race
        // harmless even if this line is ever removed.
        safeShutdownStep("Redaction truncation sink") { Redaction.truncationLogger = null }
        AuditLogger.registerGlobalEmitter(null)
        // (5) The extension-owned MCP dispatcher, then whatever pool a component left running.
        safeShutdownStep("MCP coroutines") { McpCoroutines.close(deadline, ::logError) }
        safeShutdownStep("Thread sweep") { ExtensionThreads.terminateAll(deadline, ::logError) }
        // (6) Production unload only (D-12).
        if (shutdownSharedCoroutines) {
            safeShutdownStep("Shared coroutine dispatchers") { McpCoroutines.shutdownSharedDispatchers(deadline, ::logError) }
        }
    }

    /**
     * Installs every [ExtensionPlugin] on the extension's classpath. A plug-in whose install throws is
     * logged to Burp's error output and skipped, and the extension still loads (T-29-35).
     */
    private fun installExtensionPlugins() {
        val host =
            PluginHost(
                api = api,
                pluginSettings = settingsRepo.pluginSettings(),
                passiveScanner = passiveAiScanner,
                activeScanner = activeAiScanner,
                log = api.logging()::logToOutput,
            )
        installedPlugins =
            loadExtensionPlugins { error -> api.logging().logToError("Extension plug-in failed to load: ${error.message}") }
                .filter { plugin ->
                    try {
                        plugin.install(host)
                        true
                    } catch (e: Exception) {
                        api.logging().logToError("Extension plug-in ${plugin.javaClass.name} failed to install: ${e.message}")
                        false
                    }
                }
    }

    private fun configureRollingLoggerFromProperties() {
        val enabled = System.getProperty("burp.ai.logger.rolling.enabled")?.toBooleanStrictOrNull() ?: false
        if (!enabled) {
            aiRequestLogger.configureRollingPersistence(null)
            return
        }

        val directory =
            System
                .getProperty("burp.ai.logger.rolling.dir")
                ?.takeIf { it.isNotBlank() }
                ?: Paths.get(System.getProperty("user.home"), ".burp-ai-agent", "logs").toString()
        val maxBytes =
            System.getProperty("burp.ai.logger.rolling.maxBytes")?.toLongOrNull()
                ?: AiRequestLogger.DEFAULT_ROLLING_MAX_FILE_BYTES
        val maxFiles =
            System.getProperty("burp.ai.logger.rolling.maxFiles")?.toIntOrNull()
                ?: AiRequestLogger.DEFAULT_ROLLING_MAX_FILES

        aiRequestLogger.configureRollingPersistence(
            RollingLogConfig(
                directory = Paths.get(directory),
                maxFileBytes = maxBytes,
                maxFiles = maxFiles,
            ),
        )
        api.logging().logToOutput("AI logger rolling persistence enabled at $directory")
    }

    /**
     * Runs one unload step. [ready] is false for a component a partial load never built, and the step is
     * skipped. A Throwable from the step is logged and the unload goes on to the next step.
     */
    @Suppress("TooGenericExceptionCaught") // whatever a step throws, the remaining unload steps must still run
    private fun safeShutdownStep(
        component: String,
        ready: Boolean = true,
        action: () -> Unit,
    ) {
        if (!ready) return
        try {
            action()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            logError("$component shutdown interrupted")
        } catch (t: Throwable) {
            logError("$component shutdown failed: ${t.message}")
        }
    }

    /** Writes [message] to Burp's error output, or to System.err when no load ever set [api]. */
    private fun logError(message: String) {
        if (this::api.isInitialized) {
            runCatching { api.logging().logToError(message) }
        } else {
            System.err.println(message)
        }
    }
}

/**
 * Phase 29 / BUILD-03 (D-04 amended) — the Burp extension name, identical in both flavors.
 *
 * Burp keys an extension's preferences node by this name, so one name means one node: the full build
 * keeps reading the settings and encrypted secrets an earlier install wrote. Byte-exact on purpose
 * (15 characters, no surrounding whitespace), pinned by ExtensionNameTest and FullExtensionNameTest.
 */
const val EXTENSION_NAME = "Custom AI Agent"

/**
 * Phase 29 / D-02 — every [ExtensionPlugin] provider (none on the store classpath). A provider that
 * cannot be instantiated is reported to [onError] and the result is empty, so extension load continues.
 */
internal fun loadExtensionPlugins(onError: (Throwable) -> Unit = {}): List<ExtensionPlugin> =
    try {
        Plugins.load(ExtensionPlugin::class.java)
    } catch (e: ServiceConfigurationError) {
        onError(e)
        emptyList()
    }

/**
 * Phase 29 — the running flavor's [FlavorProfile]: the full build's provider when its services file is
 * on the classpath, otherwise the core [StoreFlavorProfile]. More than one provider falls back to the
 * store default after [onConflict] receives the provider class names.
 */
internal fun resolveFlavorProfile(onConflict: (List<String>) -> Unit = {}): FlavorProfile = Plugins.single(FlavorProfile::class.java, onConflict) ?: StoreFlavorProfile()

/**
 * Phase 29 / BUILD-04 — the running flavor's [AiAccessPolicy]: the full build's provider when its
 * services file is on the classpath, otherwise the strict core [StoreAiAccessPolicy]. More than one
 * provider also resolves to [StoreAiAccessPolicy] after [onConflict] receives the provider class names,
 * so a packaging error can only make the build stricter.
 */
internal fun resolveAiAccessPolicy(onConflict: (List<String>) -> Unit = {}): AiAccessPolicy = Plugins.single(AiAccessPolicy::class.java, onConflict) ?: StoreAiAccessPolicy()

/**
 * Phase 29 — the ONLY place the extension names itself to Burp. The name is [EXTENSION_NAME] in every
 * flavor; [profile] only labels the load banner so the Output tab says which build is running.
 */
internal fun registerExtensionIdentity(
    api: MontoyaApi,
    profile: FlavorProfile,
) {
    api.extension().setName(EXTENSION_NAME)
    api.logging().logToOutput(buildIdentityLine(profile))
}

/**
 * Phase 29 / UI-SPEC PC-15 (S3, S25, C-N12): the one string that names the running build, for example
 * `Custom AI Agent 1.0.1 (BApp Store build)`. [registerExtensionIdentity] logs it as the Output banner
 * and App passes the same value down to the Settings Help caption. The label is shown, never compared.
 */
internal fun buildIdentityLine(profile: FlavorProfile): String = "$EXTENSION_NAME ${BuildFlags.VERSION} (${profile.label})"

/**
 * Quick 261008-n0c — makes [AgentSupervisor]'s settings copy a mirror of the one [settingsRepo].
 *
 * AgentSupervisor keeps its own AtomicReference because its launch config (backend commands, URLs,
 * keys, MCP env) reads settings off the EDT. This listener updates it inside every
 * successful save, including MainTab's header writes (backend picker, scanner and MCP toggles), which
 * never call `supervisor.applySettings` themselves.
 */
internal fun mirrorAppliedSettingsInto(
    settingsRepo: AgentSettingsRepository,
    supervisor: AgentSupervisor,
) {
    settingsRepo.addChangeListener { supervisor.applySettings(it) }
}

/**
 * Phase 31 / D-15 — the one Output line App writes at load stating Burp's edition and what
 * `api.ai().isEnabled()` returned, or that it threw and with which exception class. It is the
 * measurement Phase 35's edition requirements come from, read in Community and Professional by the
 * D-15 manual UAT.
 *
 * Reading `isEnabled()` is local and sends no request. Unlike `AgentSupervisor.isAiEnabled`, which
 * swallows a throw and answers `false`, this reports the throw, because whether the call throws is part
 * of what D-15 measures. Only the exception's simple class name and message are included: no settings,
 * keys or traffic.
 *
 * `TooGenericExceptionCaught` is suppressed on purpose (ADR-17): any Montoya failure must become text in
 * this line, never abort extension load.
 */
@Suppress("TooGenericExceptionCaught")
internal fun burpAiLoadDiagnostics(api: MontoyaApi): String {
    val edition = burpEditionName(api)
    val aiState =
        try {
            "= ${api.ai().isEnabled()}"
        } catch (e: Exception) {
            "threw ${e.javaClass.simpleName}: ${e.message}"
        }
    return "[Diagnostics] Burp $edition at load: api.ai().isEnabled() $aiState"
}

/**
 * Burp's edition name for [burpAiLoadDiagnostics], or `unknown edition` when the lookup throws. The catch
 * is deliberately broad and swallowing (ADR-17): the line must still report isEnabled() when the edition
 * cannot be read.
 */
@Suppress("TooGenericExceptionCaught", "SwallowedException")
private fun burpEditionName(api: MontoyaApi): String =
    try {
        api
            .burpSuite()
            .version()
            .edition()
            .name
    } catch (_: Exception) {
        "unknown edition"
    }
