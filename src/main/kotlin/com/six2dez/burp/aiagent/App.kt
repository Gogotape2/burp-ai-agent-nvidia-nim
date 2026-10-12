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
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.SafeRegex
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.AiPassiveScanCheck
import com.six2dez.burp.aiagent.scanner.AiScanCheck
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.applyOptimizationSettings
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.MainTab
import com.six2dez.burp.aiagent.ui.UiActions
import java.nio.file.Paths

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

    fun initialize(montoyaApi: MontoyaApi) {
        api = montoyaApi
        registerExtensionIdentity(
            api,
            resolveFlavorProfile { providers ->
                api.logging().logToError(
                    "More than one FlavorProfile provider found (${providers.joinToString(", ")}); " +
                        "using the BApp Store default.",
                )
            },
        )

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
        mirrorAppliedSettingsInto(settingsRepo, supervisor)
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
        passiveAiScanner.activeScanner = activeAiScanner // Wire passive -> active
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

        val ui = MainTab(api, settingsRepo, backendRegistry, supervisor, auditLogger, mcpSupervisor, passiveAiScanner, activeAiScanner, aiRequestLogger)
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

    fun shutdown() {
        safeShutdownStep("MainTab") { mainTab?.shutdown() }
        mainTab = null
        safeShutdownStep("AI Request Logger") { aiRequestLogger.shutdown() }
        safeShutdownStep("Passive scanner") {
            passiveAiScanner.setEnabled(false)
            passiveAiScanner.shutdown()
        }
        // Split so a throw in setEnabled(false) can't skip shutdown() — shutdown() is the only
        // place the per-request requestExecutor (a cached thread pool) is terminated on unload.
        safeShutdownStep("Active scanner disable") { activeAiScanner.setEnabled(false) }
        safeShutdownStep("Active scanner") { activeAiScanner.shutdown() }
        safeShutdownStep("Supervisor") { supervisor.shutdown() }
        safeShutdownStep("MCP supervisor") { mcpSupervisor.shutdown() }
        // REL-07 / SC5 / D-03: each backend's shutdown() runs inside this step, after the supervisor has
        // stopped. In the full build that drains the CLI temp-file registry (T-24-07; see
        // BackendRegistry.shutdown()).
        safeShutdownStep("Backend registry") { backendRegistry.shutdown() }
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

    private fun safeShutdownStep(
        component: String,
        action: () -> Unit,
    ) {
        try {
            action()
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            api.logging().logToError("$component shutdown interrupted")
        } catch (e: Exception) {
            api.logging().logToError("$component shutdown failed: ${e.message}")
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
    api.logging().logToOutput("$EXTENSION_NAME ${BuildFlags.VERSION} (${profile.label})")
}

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
