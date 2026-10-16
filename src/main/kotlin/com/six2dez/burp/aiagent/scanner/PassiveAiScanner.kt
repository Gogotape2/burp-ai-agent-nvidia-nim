package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.spi.SuggestedTargetSink
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.BudgetGuard
import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import java.util.LinkedHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class PassiveAiScanner(
    internal val api: MontoyaApi,
    internal val supervisor: AgentSupervisor,
    internal val audit: AuditLogger,
    internal val getSettings: () -> AgentSettings,
) {
    var aiRequestLogger: AiRequestLogger? = null

    private val enabled = AtomicBoolean(false)

    /** CAP-04: per-process budget pause gate. Starts false each Burp run (reversible). */
    private val budgetPaused = AtomicBoolean(false)

    fun setBudgetPaused(on: Boolean) {
        budgetPaused.set(on)
    }

    fun isBudgetPaused(): Boolean = budgetPaused.get()

    /**
     * CAP-04 single budget-consultation point (RESEARCH Open-Q2): evaluate the per-session token
     * budget against the live session totals and drive the pause gate in BOTH directions.
     *
     * - [BudgetGuard.State.CAP] → [setBudgetPaused] `true` (pause passive scanning).
     * - [BudgetGuard.State.WARN] / [BudgetGuard.State.OFF] → [setBudgetPaused] `false` (resume),
     *   which makes the gate genuinely reversible (its KDoc contract) once the cap is raised,
     *   cleared, or usage drops back below it.
     *
     * Called from the scanner's own token-record sites (so a scanner-only run trips the cap —
     * WR-01) and from the chat / settings-apply paths so chat and scanner share ONE evaluation.
     * Returns the resulting [BudgetGuard.State] so EDT callers can refresh their banner from the
     * same decision without re-evaluating. Stays AWT-free: no Swing access here.
     */
    fun reconcileBudget(settings: AgentSettings): BudgetGuard.State {
        val state =
            BudgetGuard.evaluate(
                BudgetGuard.currentSessionTokens(),
                settings.tokenBudgetWarnThreshold,
                settings.tokenBudgetHardCap,
            )
        setBudgetPaused(state == BudgetGuard.State.CAP)
        return state
    }

    internal val requestsAnalyzed = AtomicInteger(0)
    internal val issuesFound = AtomicInteger(0)
    internal val lastAnalysisTime = AtomicLong(0)
    internal val aiBackoffUntilMs = AtomicLong(0)
    internal val lastBackoffLogTime = AtomicLong(0)

    /** D-11: the single passive analysis worker, the daemon `burp-ai-agent-passive-scan`. */
    internal val executor = ExtensionThreads.singleThread("passive-scan")

    /**
     * Phase 33 / SC3: set once unload began. From then on no analysis may start a provider request:
     * [flushBatch] and [sendSingleAnalysis] return first when it is set, and every send site (those two
     * and [doAnalysis]'s single-request send) checks it again right before sending, because the backend
     * check before a send can outlast the start of unload. Never reset: the scanner is not reused after
     * [shutdown].
     */
    @Volatile
    internal var shuttingDown = false
    internal val findings = ArrayDeque<PassiveAiFinding>(Defaults.FINDINGS_BUFFER_SIZE)

    /**
     * Phase 32 / D-01..D-09: every suggested target of a new finding lands here, in both builds. The
     * user sees the list and queues entries by hand after a confirmation; collecting them sends
     * nothing. It is a `val`, so a plug-in cannot replace or remove it. Session-only: cleared in
     * [shutdown].
     */
    val suggestedTargets = SuggestedTargetList()

    /**
     * Phase 29 / D-02: the plug-in slot for suggested targets, and only that. Null in the store build,
     * which installs no plug-in. The full build's opt-in auto-queue plug-in sets it on install and
     * clears it on unload. It is offered the same targets after [suggestedTargets] has them.
     */
    @Volatile
    var suggestedTargetSink: SuggestedTargetSink? = null

    // Configurable settings with defaults
    var rateLimitSeconds: Int = 5
    var scopeOnly: Boolean = true
    var maxSizeKb: Int = 96

    @Volatile
    var endpointDedupMinutes: Int = DEFAULT_ENDPOINT_DEDUP_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }

    @Volatile
    var responseFingerprintDedupMinutes: Int = DEFAULT_RESPONSE_FINGERPRINT_DEDUP_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }

    @Volatile
    var promptCacheTtlMinutes: Int = DEFAULT_PROMPT_CACHE_TTL_MINUTES
        set(value) {
            field = value.coerceIn(MIN_DEDUP_TTL_MINUTES, MAX_DEDUP_TTL_MINUTES)
        }

    @Volatile
    var endpointCacheEntries: Int = DEFAULT_ENDPOINT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_ENDPOINT_CACHE_ENTRIES, MAX_ENDPOINT_CACHE_ENTRIES)
            synchronized(endpointRecentCache) {
                trimLruCache(endpointRecentCache, field)
            }
        }

    @Volatile
    var responseFingerprintCacheEntries: Int = DEFAULT_RESPONSE_FINGERPRINT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_RESPONSE_FINGERPRINT_CACHE_ENTRIES, MAX_RESPONSE_FINGERPRINT_CACHE_ENTRIES)
            synchronized(responseFingerprintCache) {
                trimLruCache(responseFingerprintCache, field)
            }
        }

    @Volatile
    var promptCacheEntries: Int = DEFAULT_PROMPT_RESULT_CACHE_MAX_ENTRIES
        set(value) {
            field = value.coerceIn(MIN_PROMPT_RESULT_CACHE_ENTRIES, MAX_PROMPT_RESULT_CACHE_ENTRIES)
            synchronized(promptResultCache) {
                trimLruCache(promptResultCache, field)
            }
        }

    @Volatile
    var requestBodyPromptMaxChars: Int = DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS
        set(value) {
            field = value.coerceIn(MIN_REQUEST_BODY_PROMPT_MAX_CHARS, MAX_REQUEST_BODY_PROMPT_MAX_CHARS)
        }

    @Volatile
    var responseBodyPromptMaxChars: Int = DEFAULT_RESPONSE_BODY_PROMPT_MAX_CHARS
        set(value) {
            field = value.coerceIn(MIN_RESPONSE_BODY_PROMPT_MAX_CHARS, MAX_RESPONSE_BODY_PROMPT_MAX_CHARS)
        }

    @Volatile
    var headerMaxCount: Int = DEFAULT_HEADERS_MAX_COUNT
        set(value) {
            field = value.coerceIn(MIN_HEADERS_MAX_COUNT, MAX_HEADERS_MAX_COUNT)
        }

    @Volatile
    var paramMaxCount: Int = DEFAULT_PARAMS_MAX_COUNT
        set(value) {
            field = value.coerceIn(MIN_PARAMS_MAX_COUNT, MAX_PARAMS_MAX_COUNT)
        }

    @Volatile
    var excludedExtensions: Set<String> = DEFAULT_EXCLUDED_EXTENSIONS
        set(value) {
            field = value.map { it.lowercase().removePrefix(".") }.toSet()
        }

    internal val cacheBustingParamRegex = Regex("^(?:_|t|ts|timestamp|cachebust|cb|rnd|nonce)$", RegexOption.IGNORE_CASE)
    internal val dynamicValueStripRegex =
        Regex(
            listOf(
                """\b[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b""", // UUID
                """\b[a-f0-9]{24}\b""", // MongoDB ObjectId
                """\b\d{10,13}\b""", // Unix timestamps (sec/ms)
                """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s"',}\]]*""", // ISO 8601
                """(?<=[":=])\s*"?[A-Za-z0-9_\-]{20,}"?""", // Long tokens/nonces
            ).joinToString("|"),
            RegexOption.IGNORE_CASE,
        )
    internal val staticAssetPathRegex =
        Regex(
            "\\.(?:css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)(?:\\?|$)",
            RegexOption.IGNORE_CASE,
        )
    internal val requestHeaderAllowlist =
        setOf(
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "content-type",
            "origin",
            "referer",
            "host",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-requested-with",
        )
    internal val responseHeaderAllowlist =
        setOf(
            "set-cookie",
            "www-authenticate",
            "x-frame-options",
            "content-security-policy",
            "content-security-policy-report-only",
            "strict-transport-security",
            "x-content-type-options",
            "x-xss-protection",
            "location",
            "content-type",
            "content-disposition",
            "server",
            "x-powered-by",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
        )
    internal val headerNoiseDenylist =
        setOf(
            "accept-encoding",
            "accept-language",
            "connection",
            "keep-alive",
            "date",
            "etag",
            "last-modified",
            "vary",
            "transfer-encoding",
            "content-length",
            "accept-ranges",
            "age",
            "via",
        )

    internal val endpointRecentCache =
        object : LinkedHashMap<String, Long>(1024, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > endpointCacheEntries
        }
    internal val responseFingerprintCache =
        object : LinkedHashMap<String, Long>(2048, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > responseFingerprintCacheEntries
        }
    internal val promptResultCache =
        object : LinkedHashMap<String, CachedAiIssues>(512, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CachedAiIssues>?): Boolean = size > promptCacheEntries
        }

    internal val batchQueue = BatchAnalysisQueue()
    internal var persistentCache: com.six2dez.burp.aiagent.cache.PersistentPromptCache? = null

    fun setEnabled(on: Boolean) {
        val wasEnabled = enabled.getAndSet(on)
        if (on) {
            api.logging().logToOutput("[PassiveAiScanner] Enabled - Burp Scanner passive check active (Pro only)")
        } else if (wasEnabled) {
            // Clear accumulated knowledge to prevent cross-scope contamination
            ScanKnowledgeBase.clear()
            api.logging().logToOutput("[PassiveAiScanner] Disabled — knowledge base cleared")
        }
    }

    /** Phase 31 / D-02: set by the first refusal of this extension load; never reset during the load. */
    private val aiGateRefusalLogged = AtomicBoolean(false)

    /**
     * Phase 31 / D-02 — whether the injected AI access policy allows the backend this scanner would
     * really run (the saved id, resolved the way the supervisor resolves it). Asked before any
     * executor submit, so a refused item is skipped and dropped: it never reaches
     * [ensureBackendRunning] or `startOrAttach`, nothing logs per item and nothing is retried later.
     *
     * RESEARCH Pitfall 5: this asks [AgentSupervisor.refusalForSavedBackend], which answers with no
     * backend running. The running-backend check is false while the supervisor is idle, which let the
     * first refused item reach `startOrAttach` and log per item.
     *
     * The first refusal of the load writes one Output line carrying the policy's refusal text; later
     * refusals write nothing (the scanner panel shows the live paused state instead). The transport
     * choke point (plan 31-01) still refuses any provider request that slips past this pre-check.
     */
    private fun aiGateOpen(settings: AgentSettings): Boolean = aiGateRefusal(settings) == null

    /**
     * Phase 31 gap closure WR-04: the refusal behind [aiGateOpen], or null when the policy allows the
     * saved backend. Writes the once-per-load "Paused" Output line on the first refusal, exactly as
     * [aiGateOpen] always did, and hands the refusal text back so a manual scan can show it.
     */
    private fun aiGateRefusal(settings: AgentSettings): String? {
        val refusal = supervisor.refusalForSavedBackend(settings.preferredBackendId) ?: return null
        if (aiGateRefusalLogged.compareAndSet(false, true)) {
            api.logging().logToOutput("[PassiveAiScanner] Paused: $refusal")
        }
        return refusal
    }

    /**
     * The AI half's gates for Burp Scanner check work: the scanner is on, the token budget is not
     * paused and the AI access policy allows the saved backend ([aiGateOpen]). Serves
     * [enqueueForScanCheck] only; the local-finding bookkeeping uses [acceptsLocalFindingWork].
     */
    private fun acceptsScanCheckWork(): Boolean =
        enabled.get() &&
            // CAP-04: no-op when paused (does NOT clear KB or flip enabled)
            !budgetPaused.get() &&
            aiGateOpen(getSettings())

    /**
     * Phase 31 gap closure WR-02: the gates for the bookkeeping of the local findings the Burp Scanner
     * check files: the scanner is on and the token budget is not paused. The local heuristics send no
     * AI request, so the bookkeeping of what Burp files from them does not depend on the AI access policy.
     */
    private fun acceptsLocalFindingWork(): Boolean =
        enabled.get() &&
            // CAP-04: unchanged; issues filed under a budget pause still skip their bookkeeping
            !budgetPaused.get()

    /**
     * Enqueues a request/response for asynchronous AI deep-analysis.
     * Called by AiPassiveScanCheck.doCheck() after the check filed the local findings itself, so the
     * analysis does not file them again but still uses them to decide whether to skip the AI call.
     * Returns immediately — AI findings surface later via api.siteMap().add().
     */
    fun enqueueForScanCheck(requestResponse: HttpRequestResponse) {
        if (!acceptsScanCheckWork()) return
        executor.submit { analyzeManually(requestResponse, localIssuesFiledByScanCheck = true) }
    }

    /**
     * Records the side effects of the local findings AiPassiveScanCheck.doCheck() has just filed in its
     * AuditResult (quick 261009-1ao): counter, Output line, knowledge-base signal, auto-queue,
     * `passive_ai_issue` audit record and findings buffer, once per new issue, consolidated on repeats.
     * Gated by [acceptsLocalFindingWork]: recorded whenever the scanner is on and the token budget is
     * not paused, whatever the AI access policy says (Phase 31 gap closure WR-02, D-02, D-07); nothing
     * is recorded while the scanner is off or the budget is paused. The AI half
     * ([enqueueForScanCheck]) keeps the AI gate, so a refused policy still sends nothing.
     *
     * Runs synchronously, before doCheck returns: the consolidation check reads the site map, and on the
     * executor it would race Burp adding the check's own, same-named issue and usually see it, dropping
     * the side effects of the very first finding. Before doCheck returns it sees only earlier issues.
     */
    internal fun recordScanCheckFindings(
        requestResponse: HttpRequestResponse,
        filed: List<LocalFinding>,
    ) {
        if (filed.isEmpty() || !acceptsLocalFindingWork()) return
        val settings = getSettings()
        filed.forEach { finding -> recordFiledLocalFinding(requestResponse, finding, settings) }
    }

    /**
     * Package-internal wrapper for the private runLocalChecks() method.
     * Called by AiPassiveScanCheck.doCheck() synchronously to get fast heuristic findings.
     */
    internal fun localChecks(
        request: burp.api.montoya.http.message.requests.HttpRequest,
        response: burp.api.montoya.http.message.responses.HttpResponse?,
    ): List<LocalFinding> =
        runLocalChecks(
            request,
            response,
            request.bodyToString().take(REQUEST_BODY_LOCAL_CHECK_MAX_CHARS),
            response?.bodyToString().orEmpty().take(RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS),
        )

    // applyOptimizationSettings is a public extension function in PassiveAiScannerFilters.kt.

    fun isEnabled(): Boolean = enabled.get()

    fun getStatus(): PassiveAiScannerStatus =
        PassiveAiScannerStatus(
            enabled = enabled.get(),
            requestsAnalyzed = requestsAnalyzed.get(),
            issuesFound = issuesFound.get(),
            lastAnalysisTime = lastAnalysisTime.get(),
            queueSize = 0, // Single-threaded executor
            // Phase 31 / D-02: computed from the live policy on every refresh (local, no request).
            aiGatePaused = enabled.get() && supervisor.refusalForSavedBackend(getSettings().preferredBackendId) != null,
        )

    fun getLastFindings(n: Int): List<PassiveAiFinding> {
        if (n <= 0) return emptyList()
        synchronized(findings) {
            return if (findings.size <= n) findings.toList() else findings.takeLast(n)
        }
    }

    /** Unloads with a fresh, whole unload budget; see the overload taking a [ShutdownDeadline]. */
    fun shutdown() = shutdown(ShutdownDeadline.unload())

    /**
     * Phase 33 / SC3, LIFE-02: unloading sends nothing to the AI backend and waits on no AI request.
     *
     * - No flush. A partly filled batch used to be flushed here, synchronously: an AI request carrying
     *   observed traffic, made on Burp's unload path, that the unload then waited on. It is now dropped.
     * - `shutdownNow`, not `shutdown`. A plain `shutdown` lets the queued analyses run, and each would
     *   send observed traffic to the provider during unload. `shutdownNow` discards them and interrupts
     *   the running one; [shuttingDown] (set first) stops an analysis already past its entry gates
     *   before its send, and an interrupted analysis ends without an Error line.
     * - What was dropped (batch items plus queued analyses) is counted in ONE Output line,
     *   `[PassiveAiScanner] Unload: dropped N pending passive analysis item(s); nothing was sent to the
     *   AI backend.`, and nothing is written when nothing was dropped.
     * - The executor wait uses only what is left of the shared unload [deadline] (D-05); a worker that
     *   does not stop in time costs one Error line naming "Passive scanner" (D-09).
     *
     * [suggestedTargets] is cleared last, after the executor stopped (Phase 32 D-06 / WR-01).
     */
    fun shutdown(deadline: ShutdownDeadline) {
        enabled.set(false)
        shuttingDown = true
        val droppedBatch = batchQueue.size()
        batchQueue.clear()
        val droppedQueued = executor.shutdownNow().size
        val dropped = droppedBatch + droppedQueued
        if (dropped > 0) {
            runCatching {
                api.logging().logToOutput(
                    "[PassiveAiScanner] Unload: dropped $dropped pending passive analysis item(s); " +
                        "nothing was sent to the AI backend.",
                )
            }
        }
        deadline.awaitOrForce(executor, "Passive scanner") { line -> runCatching { api.logging().logToError(line) } }
        ExtensionThreads.release(executor)
        // D-06 / 32-REVIEW WR-01: emptied after the drain, so an analysis still in flight cannot
        // refill the list; the latch also refuses adds from Burp passive-scan threads. Collection is
        // deliberately not gated on the enabled flag, because manual scans run with it off (D-09).
        suggestedTargets.clear(refuseLaterAdds = true)
    }

    fun resetStats() {
        requestsAnalyzed.set(0)
        issuesFound.set(0)
        synchronized(findings) { findings.clear() }
    }

    // Manual scan tracking
    private val manualScanTotal = AtomicInteger(0)
    private val manualScanCompleted = AtomicInteger(0)
    private val manualScanInProgress = AtomicBoolean(false)

    fun getManualScanProgress(): Triple<Boolean, Int, Int> = Triple(manualScanInProgress.get(), manualScanCompleted.get(), manualScanTotal.get())

    /**
     * Manually scan a list of requests (MCP `ai_passive_scan` and other count-only callers).
     * Does not require the passive scanner to be enabled.
     * Returns the number of requests queued for analysis, 0 when nothing was queued (a refusal included).
     * Callers that show the outcome to a user call [startManualScan] instead (Phase 31 gap closure WR-04).
     */
    fun manualScan(
        requests: List<HttpRequestResponse>,
        onProgress: (Int, Int) -> Unit = { _, _ -> },
    ): Int =
        when (val start = startManualScan(requests, onProgress)) {
            is ManualPassiveScanStart.Queued -> start.count
            is ManualPassiveScanStart.Refused -> 0
        }

    /**
     * Manually scan a list of requests (from the context menu) and say what happened.
     * Does not require the passive scanner to be enabled.
     *
     * Phase 31 gap closure WR-04 / D-01, D-02: a scan the AI access policy refuses returns
     * [ManualPassiveScanStart.Refused] with the policy's refusal text, queues nothing and is not
     * retried later, so the context menu can show the refusal where the user acted. Otherwise returns
     * [ManualPassiveScanStart.Queued] with the number of requests queued.
     */
    @Suppress("ReturnCount") // body moved from manualScan (baseline-keyed on its signature); ADR-17 forbids a new entry
    fun startManualScan(
        requests: List<HttpRequestResponse>,
        onProgress: (Int, Int) -> Unit = { _, _ -> },
    ): ManualPassiveScanStart {
        if (requests.isEmpty()) return ManualPassiveScanStart.Queued(0)
        // CAP-04 / WR-01: manual passive scan is scanner work that enqueues AI analysis, so it must
        // respect the hard-cap pause just like enqueueForScanCheck (line ~356). When paused, queue
        // nothing and return a 0 count (callers already handle a 0 count) so the advertised spend
        // ceiling is a real ceiling. Does NOT clear the KB or flip the user's enabled toggle. Chat
        // stays usable.
        if (budgetPaused.get()) {
            api.logging().logToOutput("[PassiveAiScanner] Manual scan skipped — token hard cap reached")
            return ManualPassiveScanStart.Queued(0)
        }
        // Phase 31 / D-02: a refused manual scan queues nothing and is not retried later.
        aiGateRefusal(getSettings())?.let { refusal -> return ManualPassiveScanStart.Refused(refusal) }

        val total = requests.size
        manualScanTotal.set(total)
        manualScanCompleted.set(0)
        manualScanInProgress.set(true)

        api.logging().logToOutput("[PassiveAiScanner] Manual scan started: $total requests queued")

        requests.forEachIndexed { index, reqRes ->
            executor.submit {
                val url =
                    try {
                        reqRes.request().url()
                    } catch (_: Exception) {
                        "unknown"
                    }
                val shortUrl = if (url.length > 80) url.take(80) + "..." else url

                api.logging().logToOutput("[PassiveAiScanner] Analyzing [${index + 1}/$total]: $shortUrl")

                try {
                    analyzeManually(reqRes)
                } finally {
                    val completed = manualScanCompleted.incrementAndGet()
                    onProgress(completed, total)

                    if (completed >= total) {
                        manualScanInProgress.set(false)
                        val issuesCreated = issuesFound.get()
                        api.logging().logToOutput(
                            "[PassiveAiScanner] Manual scan complete: $total requests analyzed, $issuesCreated issues found",
                        )
                    }
                }
            }
        }

        return ManualPassiveScanStart.Queued(total)
    }

    // doAnalysis, analyzeManually, analyzeInBackground, flushBatch,
    // fallbackToIndividualAnalysis, sendSingleAnalysis, ensureBackendRunning,
    // redactUrlForPrompt, redactSensitiveQuery, hasExcludedExtension,
    // isGeminiCapacityError, maybeLogBackoff, extractAndLogJsEndpoints, reconcileBudgetAndLog
    // are internal extension functions in PassiveAiScannerAnalysis.kt.

    // JS endpoint discovery cache — map is owned here; extension functions access it by name.
    internal val discoveredJsEndpointsMap =
        object : java.util.LinkedHashMap<String, Long>(512, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > JS_ENDPOINTS_CACHE_MAX
        }

    private companion object {
        // Dedup TTL limits (used by @Volatile property setters)
        private const val MIN_DEDUP_TTL_MINUTES = 1
        private const val MAX_DEDUP_TTL_MINUTES = 240
        private const val DEFAULT_ENDPOINT_DEDUP_MINUTES = 30
        private const val DEFAULT_RESPONSE_FINGERPRINT_DEDUP_MINUTES = 30
        private const val DEFAULT_PROMPT_CACHE_TTL_MINUTES = 30

        // Cache entry limits
        private const val MIN_ENDPOINT_CACHE_ENTRIES = 100
        private const val MAX_ENDPOINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_ENDPOINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 100
        private const val MAX_RESPONSE_FINGERPRINT_CACHE_ENTRIES = 50_000
        private const val DEFAULT_RESPONSE_FINGERPRINT_CACHE_MAX_ENTRIES = 5_000
        private const val MIN_PROMPT_RESULT_CACHE_ENTRIES = 50
        private const val MAX_PROMPT_RESULT_CACHE_ENTRIES = 5_000
        private const val DEFAULT_PROMPT_RESULT_CACHE_MAX_ENTRIES = 500

        // Body truncation for localChecks() (called from class body)
        private const val REQUEST_BODY_LOCAL_CHECK_MAX_CHARS = 3_000
        private const val RESPONSE_BODY_LOCAL_CHECK_MAX_CHARS = 6_000

        // Prompt size limits
        private const val MIN_REQUEST_BODY_PROMPT_MAX_CHARS = 256
        private const val MAX_REQUEST_BODY_PROMPT_MAX_CHARS = 20_000
        private const val DEFAULT_REQUEST_BODY_PROMPT_MAX_CHARS = 2_000
        private const val MIN_RESPONSE_BODY_PROMPT_MAX_CHARS = 512
        private const val MAX_RESPONSE_BODY_PROMPT_MAX_CHARS = 40_000
        private const val DEFAULT_RESPONSE_BODY_PROMPT_MAX_CHARS = 4_000

        // Header/param count limits
        private const val MIN_PARAMS_MAX_COUNT = 5
        private const val MAX_PARAMS_MAX_COUNT = 100
        private const val DEFAULT_PARAMS_MAX_COUNT = 15
        private const val MIN_HEADERS_MAX_COUNT = 5
        private const val MAX_HEADERS_MAX_COUNT = 120
        private const val DEFAULT_HEADERS_MAX_COUNT = 40

        // JS endpoint discovery cache size (used by discoveredJsEndpointsMap field init)
        private const val JS_ENDPOINTS_CACHE_MAX = 2_000

        val DEFAULT_EXCLUDED_EXTENSIONS = Defaults.DEFAULT_EXCLUDED_EXTENSIONS
    }
}
