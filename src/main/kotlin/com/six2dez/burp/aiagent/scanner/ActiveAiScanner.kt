package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.IssueUtils
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import com.six2dez.burp.aiagent.util.scheduleGuarded
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.abs

data class ActiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
)

// Finding #7 (BApp #231): a Collaborator payload awaiting an out-of-band interaction. A single
// shared poller matches interactions against these and creates the confirmed issue asynchronously.
private data class PendingOast(
    val target: ActiveScanTarget,
    val baseline: HttpRequestResponse,
    val exploitRequestResponse: HttpRequestResponse,
    val oastUrl: String,
    val registeredAtMs: Long,
)

private const val OAST_POLL_INTERVAL_SECONDS = 60L

/** Phase 33 / D-04: the one local wait an OFF toggle gives the worker and scheduler pools, together. */
private const val TOGGLE_STOP_BUDGET_MS = 5_000L

/**
 * AI-powered Active Scanner that confirms vulnerabilities by sending test payloads
 */
class ActiveAiScanner(
    private val api: MontoyaApi,
    private val supervisor: AgentSupervisor,
    private val audit: AuditLogger,
    private val getSettings: () -> AgentSettings,
) {
    private val enabled = AtomicBoolean(false)
    private val scanning = AtomicBoolean(false)
    private val scanQueue = ConcurrentLinkedQueue<ActiveScanTarget>()
    private val processedTargets = ConcurrentHashMap<String, Long>() // Dedup
    private val issueLock = ReentrantLock()
    private val scansCompleted = AtomicInteger(0)
    private val vulnsConfirmed = AtomicInteger(0)
    private val currentTarget = AtomicReference<String?>(null)
    private val confirmations = ArrayDeque<ActiveAiFinding>(Defaults.FINDINGS_BUFFER_SIZE)

    private val payloadGenerator = PayloadGenerator()
    private val adaptivePayloadEngine = AdaptivePayloadEngine(supervisor)
    private val responseAnalyzer = ResponseAnalyzer()

    // REL-07 / SC6: the per-request pool, bounded, named and daemon. Shape is deliberate and each
    // argument answers a measured failure:
    //  - core 0 + SynchronousQueue preserves the cached pool's direct hand-off latency. This pool
    //    feeds a future.get(timeout) that is already time-bounded, so a work queue in front of it
    //    would only add delay before a call that cannot wait anyway.
    //  - a FIXED pool is forbidden here. Montoya does not document api.http().sendRequest as
    //    interruptible, so future.cancel(true) can orphan a request thread per timeout; with a
    //    fixed pool every later submit would queue behind the orphans and every future.get would
    //    time out, degrading the scanner to "every request returns null" with nothing in the error
    //    log — silently worse than the unbounded pool this replaces.
    //  - the ceiling is a constant, not a function of maxConcurrent: this is a val initialised at
    //    construction, while maxConcurrent is a mutable var written later from settings.
    //  - AbortPolicy makes saturation observable. Its throw site is handled in
    //    sendRequestWithTimeout (returns null) and on the scheduler thread by scheduleGuarded.
    //  - Phase 33 / D-11: the pool comes from the thread helper, which names its daemon threads
    //    burp-ai-agent-scan-request-N and tracks it for the unload sweep.
    private val requestExecutor: ExecutorService =
        ExtensionThreads.boundedPool(
            "scan-request",
            0,
            Defaults.MAX_SCAN_REQUEST_THREADS,
            Defaults.SCAN_REQUEST_THREAD_KEEPALIVE_SECONDS,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            ThreadPoolExecutor.AbortPolicy(),
        )

    // Phase 33 / D-04, EDT-01: every start and stop runs under this lock. UI code never takes it: it
    // calls requestEnabled, which hands the transition to the one lifecycle thread below, so a stop that
    // waits for busy workers never blocks the EDT and two clicks run one after the other (FIFO).
    private val lifecycleLock = ReentrantLock()
    private val lifecycle: ExecutorService = ExtensionThreads.singleThread("scan-lifecycle")

    /** Lifecycle requests submitted and not yet finished; `stopping` is reported from this. */
    private val pendingTransitions = AtomicInteger(0)

    /** Set by [shutdown]; once true nothing starts again for the rest of the load. */
    @Volatile
    private var terminated = false

    /** Set by a stop, cleared by the next start; read by [haltRequested] on the workers (D-02). */
    @Volatile
    private var stopIssued = false

    // Finding #7 (BApp #231): SSRF out-of-band confirmation is asynchronous. A single shared
    // Collaborator client + one scheduled poller replace the old per-target client that blocked a
    // scanner thread polling getAllInteractions() every 500 ms for up to 30 s.
    private val oastLock = ReentrantLock()
    private var collaboratorClient: CollaboratorClient? = null
    private val pendingOast = ConcurrentHashMap<String, PendingOast>()

    @Volatile
    private var oastPoller: ScheduledExecutorService? = null

    // Quick 261008-vau: one baseline per original request, shared by all of its targets (points x
    // classes, manual and passive-driven). Bounded by size and age, dropped in stopProcessing.
    private val baselineCache = ScanBaselineCache()

    private val headerInjectionAllowlist = ScannerUtils.HEADER_INJECTION_ALLOWLIST
    private val authHeaderNames =
        setOf(
            "authorization",
            "x-api-key",
            "x-auth-token",
            "x-access-token",
            "x-csrf-token",
        )
    private val authCookieHint = Regex("(session|auth|token|sid|jwt|remember)", RegexOption.IGNORE_CASE)
    private val authErrorRegex =
        Regex(
            "(unauthorized|forbidden|access denied|not authorized|login|sign\\s?in|signin)",
            RegexOption.IGNORE_CASE,
        )
    private val sensitiveDataRegex =
        Regex(
            "email.*@|password|credit.*card|ssn|api.*key",
            RegexOption.IGNORE_CASE,
        )
    private val staticAssetRegex =
        Regex(
            "\\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ico|map)(\\?|$)",
            RegexOption.IGNORE_CASE,
        )

    // Written under lifecycleLock, read by the scheduler tick, the settings setters and getStatus.
    @Volatile
    private var executor: ExecutorService? = null

    @Volatile
    private var scheduledExecutor: ScheduledExecutorService? = null

    // Configurable limits. Written on the EDT / Save worker and read live by the scan workers and the
    // scheduler tick, so a new value applies to the next target without a restart (Phase 33 / D-01).

    /**
     * How many targets are scanned at once, at least 1.
     *
     * Phase 33 / D-01: setting it on a running scanner resizes the live worker pool (core and maximum
     * both become the new value), so the pool never exceeds it. This replaces the restart-per-change
     * that left the old pool's workers attacking alongside the new one (review H14). Never takes the
     * lifecycle lock: it runs on the EDT. A pool that was just shut down accepts the resize harmlessly.
     */
    @Volatile
    var maxConcurrent: Int = 3
        set(value) {
            val size = value.coerceAtLeast(1)
            field = size
            resizeWorkers(size)
        }

    @Volatile
    var maxPayloadsPerPoint: Int = 10

    @Volatile
    var timeoutSeconds: Int = 30

    @Volatile
    var requestDelayMs: Long = 100

    // Written on the EDT / Save worker, read by scan workers: payload filtering, the IDOR/BOLA gate
    // and 403 method switching all read this one field (quick 261008-vau).
    @Volatile
    var maxRiskLevel: PayloadRisk = PayloadRisk.SAFE

    @Volatile
    var scopeOnly: Boolean = true

    @Volatile
    var scanMode: ScanMode = ScanMode.FULL

    @Volatile
    var useCollaborator: Boolean = false

    @Volatile
    var maxQueueSize: Int = Defaults.ACTIVE_SCAN_MAX_QUEUE_SIZE

    /**
     * Turns the scanner on or off and returns once the transition is done. For the load path and tests:
     * an OFF waits (bounded) for busy workers, so NEVER call it on the EDT; UI code calls
     * [requestEnabled].
     *
     * Idempotent (Phase 33 / D-01): ON while the scanner already runs keeps the running pools, the
     * shared baselines and the pending Collaborator confirmations; OFF on a stopped scanner only drops
     * what is left of them.
     */
    fun setEnabled(value: Boolean) {
        enabled.set(value)
        lifecycleLock.withLock { applyCurrentIntent() }
    }

    /**
     * Phase 33 / D-04, EDT-01 — the non-blocking toggle for UI callers.
     *
     * Records the intent at once (so [isEnabled] and [getStatus] answer it immediately) and runs the start
     * or stop on the daemon `burp-ai-agent-scan-lifecycle` thread. While an OFF is in progress
     * [ActiveScannerStatus.stopping] is true, so the UI can show "Stopping…". Requests run one at a time
     * in the order they were made, and each applies the intent current when it runs, so the final state
     * follows the latest request. [onSettled] runs on the lifecycle thread once this request's transition
     * finished (or at once after [shutdown]); a throw from it is ignored.
     *
     * Never takes the lifecycle lock on the calling thread.
     */
    fun requestEnabled(
        value: Boolean,
        onSettled: (() -> Unit)? = null,
    ) {
        enabled.set(value)
        pendingTransitions.incrementAndGet()
        val transition =
            Runnable {
                try {
                    lifecycleLock.withLock { applyCurrentIntent() }
                } finally {
                    pendingTransitions.decrementAndGet()
                    onSettled?.let { runCatching { it() } }
                }
            }
        try {
            lifecycle.execute(transition)
        } catch (_: RejectedExecutionException) {
            // INTENTIONAL: the scanner was shut down (unload); there is nothing left to start or stop.
            pendingTransitions.decrementAndGet()
            onSettled?.let { runCatching { it() } }
        }
    }

    /** Resizes the live worker pool, if any, to exactly [size] threads (D-01). */
    private fun resizeWorkers(size: Int) {
        val pool = executor as? ThreadPoolExecutor ?: return
        // The JDK rejects a core size above the maximum, so the order depends on the direction.
        if (size > pool.maximumPoolSize) {
            pool.maximumPoolSize = size
            pool.corePoolSize = size
        } else {
            pool.corePoolSize = size
            pool.maximumPoolSize = size
        }
    }

    /**
     * Phase 33 / D-02 — whether a payload loop must stop: OFF interrupted this worker, or the scanner
     * was stopped since it last started (a backstop for an interrupt some callee swallowed). A scanner
     * that was never started does not halt, so `executeScan` still runs when driven directly.
     */
    private fun haltRequested(): Boolean = Thread.currentThread().isInterrupted || (stopIssued && !scanning.get())

    /**
     * The payload-loop head check (D-02): the elements of this list, lazily, until [haltRequested]. The
     * check runs before each iteration, so a loop over it ends as soon as OFF interrupts the worker.
     * Kept out of the loop bodies so the baseline-keyed scan functions keep their signatures.
     */
    private fun <T> Iterable<T>.untilHalted(): Sequence<T> = asSequence().takeWhile { !haltRequested() }

    /** Applies the current intent. The caller holds [lifecycleLock]. */
    private fun applyCurrentIntent() {
        if (enabled.get()) startIfIdle() else stopProcessing()
    }

    /** Starts the pools unless they already run or the scanner was shut down. The caller holds [lifecycleLock]. */
    private fun startIfIdle() {
        if (enabled.get() && !scanning.get() && !terminated) startProcessing()
    }

    /**
     * A manual scan asks for processing without starting it inline (EDT-01): the start is handed to the
     * lifecycle thread, so a manual scan run on the EDT while a stop is in progress does not wait for it.
     */
    private fun requestProcessing() {
        try {
            lifecycle.execute { lifecycleLock.withLock { startIfIdle() } }
        } catch (_: RejectedExecutionException) {
            // INTENTIONAL: the scanner was shut down (unload); nothing may start now.
        }
    }

    fun isEnabled(): Boolean = enabled.get()

    /** Phase 31 / D-02: set by the first refusal of this extension load; never reset during the load. */
    private val aiGateRefusalLogged = AtomicBoolean(false)

    /**
     * Phase 31 / D-02 — whether the injected AI access policy allows the backend this scanner's AI
     * calls would really use (the saved id, resolved the way the supervisor resolves it). Asked in
     * [tryQueueTarget] before anything is queued, so a refused target is dropped and never retried.
     *
     * RESEARCH Pitfall 5: [AgentSupervisor.refusalForSavedBackend] answers with no backend running;
     * the running-backend check is false while the supervisor is idle and let refused work through.
     *
     * The first refusal of the load writes one Output line carrying the policy's refusal text; later
     * refusals write nothing (the scanner panel shows the live paused state). The transport choke
     * point (plan 31-01) still refuses any provider request that slips past this pre-check. Targets
     * already in flight when Use AI turns off finish (D-04); nothing is cancelled here.
     */
    private fun aiGateOpen(settings: AgentSettings): Boolean {
        val refusal = supervisor.refusalForSavedBackend(settings.preferredBackendId) ?: return true
        if (aiGateRefusalLogged.compareAndSet(false, true)) {
            api.logging().logToOutput("[ActiveAiScanner] Paused: $refusal")
        }
        return false
    }

    fun getStatus(): ActiveScannerStatus =
        ActiveScannerStatus(
            enabled = enabled.get(),
            queueSize = scanQueue.size,
            scanning = scanning.get(),
            scansCompleted = scansCompleted.get(),
            vulnsConfirmed = vulnsConfirmed.get(),
            currentTarget = currentTarget.get(),
            // Phase 33 / D-04: an OFF request is queued or running on the lifecycle thread.
            stopping = !enabled.get() && pendingTransitions.get() > 0,
            // Phase 31 / D-02: computed from the live policy on every refresh (local, no request).
            aiGatePaused = enabled.get() && supervisor.refusalForSavedBackend(getSettings().preferredBackendId) != null,
        )

    fun getRecentConfirmations(n: Int): List<ActiveAiFinding> {
        if (n <= 0) return emptyList()
        synchronized(confirmations) {
            return if (confirmations.size <= n) confirmations.toList() else confirmations.takeLast(n)
        }
    }

    /**
     * Queue a target for active scanning, the same as [tryQueueTarget], for callers that ignore the
     * outcome.
     */
    fun queueTarget(target: ActiveScanTarget) {
        tryQueueTarget(target)
    }

    /**
     * Queue a target for active scanning and say whether it really reached the queue.
     *
     * Returns true only when the target was added to the queue. Returns false when the scanner is
     * off, the AI gate refuses (Phase 31 D-02), the class is passive-only or outside the scan mode,
     * the URL is out of scope, the target repeats inside the 1-hour window, or the queue is full.
     * Used by the full build's opt-in auto-queue to count and remove only real queues (31-REVIEW
     * IN-06).
     */
    @Suppress("ReturnCount") // body moved from queueTarget (baseline-keyed on its signature); ADR-17 forbids a new entry
    fun tryQueueTarget(target: ActiveScanTarget): Boolean {
        if (!enabled.get() || !aiGateOpen(getSettings())) return false
        if (target.vulnHint.vulnClass in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES) return false
        if (!ScanPolicy.isAllowedForMode(scanMode, target.vulnHint.vulnClass)) return false

        // Check scope
        if (scopeOnly && !api.scope().isInScope(target.originalRequest.request().url())) {
            return false
        }

        // Dedup - don't scan same target twice within 1 hour (atomic putIfAbsent)
        val now = System.currentTimeMillis()
        val existing = processedTargets.putIfAbsent(target.id, now)
        if (existing != null && (now - existing) < Defaults.DEDUP_WINDOW_MS) {
            return false
        }
        if (existing != null) {
            // Expired entry — update timestamp
            processedTargets[target.id] = now
        }

        // Boost priority if knowledge base has prior signals for this endpoint
        val boostedTarget =
            if (ScanKnowledgeBase.hasHighPrioritySignals(target.originalRequest.request().url())) {
                target.copy(priority = (target.priority + 20).coerceAtMost(100))
            } else {
                target
            }

        if (!offerIfQueueNotFull(boostedTarget)) return false
        api.logging().logToOutput("[ActiveAiScanner] Queued: ${boostedTarget.vulnHint.vulnClass} in ${boostedTarget.injectionPoint.name}")
        return true
    }

    /**
     * Manually trigger active scan on specific requests
     */
    fun manualScan(
        requests: List<HttpRequestResponse>,
        vulnClasses: List<VulnClass> = VulnClass.values().toList(),
    ): Int {
        var queued = 0
        val filteredClasses =
            vulnClasses
                .filterNot { it in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES }
                .filter { ScanPolicy.isAllowedForMode(scanMode, it) }

        for (request in requests) {
            val injectionPoints = extractInjectionPoints(request)
            for (point in injectionPoints) {
                for (vulnClass in filteredClasses) {
                    val target =
                        ActiveScanTarget(
                            originalRequest = request,
                            injectionPoint = point,
                            vulnHint = VulnHint(vulnClass, 50, "Manual scan"),
                            priority = 50,
                        )
                    if (scopeOnly && !api.scope().isInScope(request.request().url())) {
                        continue
                    }
                    if (offerIfQueueNotFull(target)) {
                        queued++
                    }
                }
            }
        }

        if (queued > 0) {
            api.logging().logToOutput("[ActiveAiScanner] Manual active scan: $queued targets queued")
            if (!scanning.get() && enabled.get()) {
                requestProcessing()
            }
        }

        return queued
    }

    /**
     * Manually scan a single, user-selected insertion point against the requested vuln classes.
     * Used by the "AI Scan on Selected Insertion Point" right-click action — the caller has
     * already resolved the parameter / header / JSON field that overlaps the editor selection,
     * so we skip [InjectionPointExtractor.extract] and queue one target per filtered vuln class.
     *
     * Like [manualScan], this bypasses the dedup `processedTargets` window used by [queueTarget]:
     * re-invoking on the same insertion point queues fresh targets each time. That matches the
     * existing manual-scan UX where the user is consciously asking for another pass.
     */
    fun manualScanInsertionPoint(
        request: HttpRequestResponse,
        insertionPoint: InjectionPoint,
        vulnClasses: List<VulnClass>,
    ): Int {
        var queued = 0
        val filteredClasses =
            vulnClasses
                .filterNot { it in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES }
                .filter { ScanPolicy.isAllowedForMode(scanMode, it) }

        if (scopeOnly && !api.scope().isInScope(request.request().url())) {
            return 0
        }

        for (vulnClass in filteredClasses) {
            val target =
                ActiveScanTarget(
                    originalRequest = request,
                    injectionPoint = insertionPoint,
                    vulnHint = VulnHint(vulnClass, 50, "Manual scan (selected insertion point)"),
                    priority = 60,
                )
            if (offerIfQueueNotFull(target)) {
                queued++
            }
        }

        if (queued > 0) {
            api
                .logging()
                .logToOutput(
                    "[ActiveAiScanner] Insertion-point scan: $queued target(s) queued for " +
                        "${insertionPoint.type}:${insertionPoint.name}",
                )
            if (!scanning.get() && enabled.get()) {
                requestProcessing()
            }
        }

        return queued
    }

    /**
     * Phase 32 / D-04 — the AI access policy's refusal text for the saved backend, or null when the
     * policy allows it. The UI asks this before it switches the scanner on for a hand-queued batch of
     * suggested targets (research A3), so a refused action never turns the scanner on. Writes no
     * Output line: the caller shows the reason in its dialog.
     */
    fun suggestedQueueRefusal(): String? = supervisor.refusalForSavedBackend(getSettings().preferredBackendId)

    /**
     * Phase 32 / D-04, D-08 — queue suggested targets because the user asked for it.
     *
     * Returns [SuggestedQueueOutcome.Refused] with the policy's text before any target is read when
     * the AI access policy refuses the saved backend. Otherwise keeps, in order, the targets whose
     * class is not passive-only, is allowed for [scanMode], whose URL passes the scope check when
     * [scopeOnly] is set, and that fit the queue, and returns them in [SuggestedQueueOutcome.Queued]
     * with the count left out.
     *
     * Like [manualScan], this ignores the 1-hour `processedTargets` window of [tryQueueTarget]: the user
     * asked explicitly, so a target the auto-queue took a moment ago is queued again (research A4).
     * The confirmation dialog is the caller's job. The AI calls of the queued scans still go through
     * the Phase 31 gate at the transport.
     */
    fun queueSuggested(targets: List<ActiveScanTarget>): SuggestedQueueOutcome {
        val refusal = suggestedQueueRefusal()
        if (refusal != null) return SuggestedQueueOutcome.Refused(refusal)

        val queued =
            targets.filter { target ->
                val vulnClass = target.vulnHint.vulnClass
                vulnClass !in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES &&
                    ScanPolicy.isAllowedForMode(scanMode, vulnClass) &&
                    (!scopeOnly || api.scope().isInScope(target.originalRequest.request().url())) &&
                    offerIfQueueNotFull(target.copy(queuedAtEpochMs = System.currentTimeMillis()))
            }

        if (queued.isNotEmpty()) {
            api.logging().logToOutput("[ActiveAiScanner] Suggested targets: ${queued.size} queued by the user")
            if (!scanning.get() && enabled.get()) {
                requestProcessing()
            }
        }

        return SuggestedQueueOutcome.Queued(queued, targets.size - queued.size)
    }

    private fun offerIfQueueNotFull(target: ActiveScanTarget): Boolean {
        if (scanQueue.size >= maxQueueSize.coerceAtLeast(1)) {
            api.logging().logToError("[ActiveAiScanner] Queue limit reached ($maxQueueSize). Dropping target: ${target.id}")
            return false
        }
        scanQueue.offer(target)
        return true
    }

    fun clearQueue() {
        scanQueue.clear()
        api.logging().logToOutput("[ActiveAiScanner] Queue cleared")
    }

    fun getQueueItems(limit: Int = 500): List<ActiveScanQueueItem> {
        val max = limit.coerceIn(1, 10_000)
        val snapshot =
            scanQueue
                .toList()
                .sortedBy { it.queuedAtEpochMs }
                .take(max)
        return snapshot.map { target ->
            ActiveScanQueueItem(
                id = target.id,
                url = target.originalRequest.request().url(),
                vulnClass = target.vulnHint.vulnClass.name,
                injectionPoint = "${target.injectionPoint.type}:${target.injectionPoint.name}",
                status = "QUEUED",
                queuedAtEpochMs = target.queuedAtEpochMs,
            )
        }
    }

    fun cancelQueuedTarget(targetId: String): Boolean {
        val match = scanQueue.firstOrNull { it.id == targetId } ?: return false
        val removed = scanQueue.remove(match)
        if (removed) {
            api.logging().logToOutput("[ActiveAiScanner] Removed queued target: $targetId")
        }
        return removed
    }

    fun resetStats() {
        scansCompleted.set(0)
        vulnsConfirmed.set(0)
        processedTargets.clear()
    }

    /** Builds and starts the pools. The caller holds [lifecycleLock]. */
    private fun startProcessing() {
        if (executor != null || scheduledExecutor != null || oastPoller != null) stopProcessing()
        stopIssued = false
        scanning.set(true)

        // REL-07 / SC6, Phase 33 / D-11: every pool comes from the thread helper, so a Burp thread dump
        // taken mid-scan names the subsystem that owns each daemon thread (burp-ai-agent-scan-worker-N,
        // burp-ai-agent-scan-scheduler, burp-ai-agent-oast-poller).
        executor = ExtensionThreads.fixedPool("scan-worker", maxConcurrent)
        // A resize that landed between building the pool and publishing it is applied now.
        resizeWorkers(maxConcurrent)
        scheduledExecutor = ExtensionThreads.scheduled("scan-scheduler")

        // REL-06: routed through scheduleGuarded so a throw on one tick cannot silently cancel the
        // queue drain for the rest of the Burp session. See util/GuardedScheduling.kt for the full
        // failure mode.
        scheduledExecutor?.scheduleGuarded(
            "ActiveAiScanner",
            "queue processing",
            { api.logging().logToError(it) },
            0,
            500,
            TimeUnit.MILLISECONDS,
        ) { processQueue() }

        // Single poller for out-of-band (Collaborator) confirmations — polls every 60 s and matches
        // interactions against pending payloads, so no scanner thread blocks waiting (BApp #231).
        oastPoller = ExtensionThreads.scheduled("oast-poller")
        oastPoller?.scheduleWithFixedDelay({
            try {
                pollOastInteractions()
            } catch (e: Throwable) {
                api.logging().logToError("[ActiveAiScanner] OAST poll failed: ${e.message}")
            }
        }, OAST_POLL_INTERVAL_SECONDS, OAST_POLL_INTERVAL_SECONDS, TimeUnit.SECONDS)
    }

    /**
     * Stops the pools (idempotent). The caller holds [lifecycleLock].
     *
     * `shutdownNow()` interrupts the workers, and the payload loops honour the interrupt (D-02). With
     * [waitForWorkers] the worker and scheduler pools then get ONE shared [TOGGLE_STOP_BUDGET_MS] wait
     * (the toggle path; it runs on the lifecycle thread or a non-EDT caller). [shutdown] passes false and
     * waits on the unload deadline instead.
     *
     * D-03: pending Collaborator confirmations, the shared baselines and the Collaborator client are
     * dropped here, on disable and unload only; a settings change no longer comes through here.
     */
    private fun stopProcessing(waitForWorkers: Boolean = true) {
        stopIssued = true
        scanning.set(false)
        val workers = executor
        val scheduler = scheduledExecutor
        val poller = oastPoller
        workers?.shutdownNow()
        scheduler?.shutdownNow()
        poller?.shutdownNow()
        if (waitForWorkers) {
            val budget = ShutdownDeadline(TOGGLE_STOP_BUDGET_MS)
            try {
                workers?.awaitTermination(budget.remainingMs(), TimeUnit.MILLISECONDS)
                scheduler?.awaitTermination(budget.remainingMs(), TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                // INTENTIONAL: thread interrupt during executor shutdown; interrupt flag restored
                Thread.currentThread().interrupt()
            }
        }
        executor = null
        scheduledExecutor = null
        oastPoller = null
        // Pools that stopped leave the helper's tracking; one still running stays tracked so the
        // unload sweep forces and reports it.
        listOfNotNull(workers, scheduler, poller).filter { it.isTerminated }.forEach { ExtensionThreads.release(it) }
        // Abandon any pending OOB confirmations, drop the shared baselines and drop the shared
        // client for a clean restart.
        pendingOast.clear()
        baselineCache.clear()
        oastLock.lock()
        try {
            collaboratorClient = null
        } finally {
            oastLock.unlock()
        }
        currentTarget.set(null)
    }

    private fun processQueue() {
        if (!enabled.get() || !scanning.get()) return

        val exec = executor ?: return

        // Process up to maxConcurrent targets
        repeat(maxConcurrent) {
            val target = scanQueue.poll() ?: return@repeat
            // REL-06 / SC2: resolved HERE, above the submit and above the try, so a failure inside
            // target.originalRequest.request() can never make the catch block itself throw. The cap
            // matches this file's existing truncation habit and bounds an attacker-influenced URL in
            // a local Burp log line; the id is URL + injection point + vulnerability class.
            val targetLabel = target.id.take(200)

            exec.submit {
                try {
                    currentTarget.set("${target.vulnHint.vulnClass}: ${target.originalRequest.request().url().take(50)}")
                    val result = executeScan(target)
                    handleResult(result)
                } catch (e: Exception) {
                    api.logging().logToError("[ActiveAiScanner] Target scan failed: $targetLabel: ${e.message}")
                } finally {
                    scansCompleted.incrementAndGet()
                    processedTargets[target.id] = System.currentTimeMillis()
                }
            }
        }

        if (scanQueue.isEmpty()) {
            currentTarget.set(null)
        }
    }

    private fun executeScan(target: ActiveScanTarget): ActiveScanResult {
        val settings = getSettings()
        val vulnClass = target.vulnHint.vulnClass

        if (vulnClass in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES) {
            return ActiveScanResult(target, 0, null, "Passive-only vulnerability class")
        }
        if (!ScanPolicy.isAllowedForMode(scanMode, vulnClass)) {
            return ActiveScanResult(target, 0, null, "Vulnerability class not enabled for scan mode")
        }

        // One risk read per target, shared by the IDOR/BOLA gate and payload filtering.
        val riskCeiling = maxRiskLevel
        if (vulnClass in ScanPolicy.IDOR_CLASSES) {
            // Checked BEFORE the baseline, so a skipped state-changing target sends nothing.
            val blockReason = ScanPolicy.idorReplayBlockReason(target.originalRequest.request().method(), riskCeiling)
            if (blockReason != null) {
                api.logging().logToOutput("[ActiveAiScanner] ${target.id.take(200)}: $blockReason")
                return ActiveScanResult(target, 0, null, blockReason)
            }
        }

        // Baseline response and time, shared by every target of the same original request
        val originalRequest = target.originalRequest.request()
        val baseline =
            baselineCache.baselineFor(
                originalRequest,
                waitTimeoutMs = timeoutSeconds.coerceAtLeast(5) * 1000L + Defaults.ACTIVE_SCAN_BASELINE_WAIT_GRACE_MS,
            ) { measureBaseline(originalRequest) }
                ?: return ActiveScanResult(target, 0, null, "Failed to send baseline request (timeout, error or no response)")
        val baselineTime = baseline.elapsedMs
        val baselineRequestResponse = baseline.requestResponse

        // 403 bypass testing: only trigger when explicitly requested via ACCESS_CONTROL_BYPASS
        val baselineStatus = baselineRequestResponse.response()?.statusCode()?.toInt() ?: 0
        if (vulnClass == VulnClass.ACCESS_CONTROL_BYPASS) {
            return execute403Bypass(target, baselineRequestResponse)
        }

        val authzConfirmation =
            if (vulnClass in ScanPolicy.AUTHZ_BYPASS_CLASSES) {
                executeAuthzBypassCheck(target, baselineRequestResponse)
            } else {
                null
            }
        if (authzConfirmation != null) {
            return ActiveScanResult(target, 0, authzConfirmation)
        }
        if (vulnClass in ScanPolicy.IDOR_CLASSES) {
            return executeIdorScan(target, baselineRequestResponse)
        }

        // Get payloads for this vulnerability class
        val quickPayloads = payloadGenerator.getQuickPayloads(vulnClass, riskCeiling)
        val contextPayloads =
            payloadGenerator.generateContextAwarePayloads(
                vulnClass,
                target.injectionPoint.originalValue,
                5,
            )

        // Generate adaptive AI payloads if enabled
        val adaptivePayloads =
            if (settings.activeAiAdaptivePayloads) {
                val host =
                    runCatching {
                        java.net
                            .URI(target.originalRequest.request().url())
                            .host
                            .orEmpty()
                    }.getOrDefault("")
                adaptivePayloadEngine.generateAdaptivePayloads(
                    vulnClass,
                    host,
                    target.injectionPoint.name,
                    target.injectionPoint.originalValue,
                    5,
                    privacyMode = settings.privacyMode,
                )
            } else {
                emptyList()
            }

        val allPayloads =
            (quickPayloads + contextPayloads + adaptivePayloads)
                .distinctBy { it.value }
                .take(maxPayloadsPerPoint)

        if (allPayloads.isEmpty()) {
            return ActiveScanResult(target, 0, null, "No payloads available for $vulnClass")
        }

        // Group Boolean-based payloads for dual confirmation testing
        val booleanPayloadPairs = mutableListOf<Pair<Payload, Payload>>()
        val truePayloads =
            allPayloads.filter {
                it.detectionMethod == DetectionMethod.BLIND_BOOLEAN &&
                    (it.value.contains("1=1") || it.value.contains("1'='1") || it.expectedEvidence.contains("Same", ignoreCase = true))
            }
        val falsePayloads =
            allPayloads.filter {
                it.detectionMethod == DetectionMethod.BLIND_BOOLEAN &&
                    (it.value.contains("1=2") || it.value.contains("1'='2") || it.expectedEvidence.contains("Different", ignoreCase = true))
            }

        // Pair TRUE and FALSE payloads for dual confirmation
        for (truePayload in truePayloads) {
            // Find matching FALSE payload (same quote style)
            val matchingFalse =
                falsePayloads.find { fp ->
                    (truePayload.value.contains("'") && fp.value.contains("'")) ||
                        (!truePayload.value.contains("'") && !fp.value.contains("'"))
                }
            if (matchingFalse != null) {
                booleanPayloadPairs.add(Pair(truePayload, matchingFalse))
            }
        }

        // Test Boolean-based payloads with DUAL CONFIRMATION
        for ((truePayload, falsePayload) in booleanPayloadPairs.untilHalted()) {
            try {
                // Test TRUE condition
                val trueRequest = injectPayload(target.originalRequest.request(), target.injectionPoint, truePayload.value)
                val trueResponse = sendRequestWithTimeout(trueRequest) ?: continue
                val trueRequestResponse = HttpRequestResponse.httpRequestResponse(trueRequest, trueResponse.response())

                Thread.sleep(requestDelayMs)

                // Test FALSE condition
                val falseRequest = injectPayload(target.originalRequest.request(), target.injectionPoint, falsePayload.value)
                val falseResponse = sendRequestWithTimeout(falseRequest) ?: continue
                val falseRequestResponse = HttpRequestResponse.httpRequestResponse(falseRequest, falseResponse.response())

                // Perform dual confirmation
                val confirmation =
                    responseAnalyzer
                        .analyzeBooleanBasedDual(
                            target.originalRequest,
                            trueRequestResponse,
                            falseRequestResponse,
                            truePayload,
                            falsePayload,
                            vulnClass,
                        )?.copy(target = target)

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, allPayloads.indexOf(falsePayload) + 1, confirmation)
                }

                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Boolean dual test error: ${e.message}")
            }
        }

        // Test non-Boolean payloads normally
        val nonBooleanPayloads = allPayloads.filter { it.detectionMethod != DetectionMethod.BLIND_BOOLEAN }
        for (payload in nonBooleanPayloads.untilHalted()) {
            try {
                // Build modified request with payload
                val modifiedRequest =
                    injectPayload(
                        target.originalRequest.request(),
                        target.injectionPoint,
                        payload.value,
                    )

                // Send request with timeout
                val startTime = System.currentTimeMillis()
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                val responseTime = System.currentTimeMillis() - startTime

                // Create HttpRequestResponse for analysis
                val modifiedRequestResponse = HttpRequestResponse.httpRequestResponse(modifiedRequest, response.response())

                // Analyze response
                val confirmation =
                    when {
                        vulnClass in ScanPolicy.CACHE_CLASSES ->
                            confirmCacheIssue(
                                target,
                                baselineRequestResponse,
                                modifiedRequestResponse,
                                payload,
                            )
                        payload.detectionMethod == DetectionMethod.BLIND_TIME -> {
                            val expectedDelay = payload.timeDelayMs ?: 3000
                            if (responseAnalyzer.analyzeTimeBased(baselineTime, responseTime, expectedDelay)) {
                                VulnConfirmation(
                                    target = target,
                                    payload = payload,
                                    originalResponse = target.originalRequest,
                                    exploitResponse = modifiedRequestResponse,
                                    confidence = 85,
                                    evidence =
                                        "Time-based detection: baseline=${baselineTime}ms, " +
                                            "payload=${responseTime}ms (expected delay: ${expectedDelay}ms)",
                                    confirmed = true,
                                )
                            } else {
                                null
                            }
                        }
                        else -> {
                            responseAnalyzer
                                .analyze(
                                    target.originalRequest,
                                    modifiedRequestResponse,
                                    payload,
                                    vulnClass,
                                )?.copy(target = target)
                        }
                    }

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, allPayloads.indexOf(payload) + 1, confirmation)
                }

                // Rate limiting
                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Payload error: ${e.message}")
            }
        }

        if (vulnClass == VulnClass.SSRF && !haltRequested()) {
            // OOB confirmation is asynchronous: register the Collaborator payload and let the shared
            // poller create the issue if an interaction arrives, instead of blocking this scanner
            // thread polling for up to 30 s (BApp #231, finding 7).
            registerSsrfoob(target, baselineRequestResponse, settings)
        }

        return ActiveScanResult(target, allPayloads.size, null)
    }

    /** Sends [request] once and times it; null when the send fails or brings no response. */
    private fun measureBaseline(request: HttpRequest): BaselineSample? {
        val start = System.currentTimeMillis()
        val response = sendRequestWithTimeout(request)?.response() ?: return null
        val elapsedMs = System.currentTimeMillis() - start
        return BaselineSample(HttpRequestResponse.httpRequestResponse(request, response), elapsedMs)
    }

    private fun executeIdorScan(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
    ): ActiveScanResult {
        if (target.injectionPoint.type !in
            setOf(
                InjectionType.URL_PARAM,
                InjectionType.BODY_PARAM,
                InjectionType.PATH_SEGMENT,
                InjectionType.JSON_FIELD,
            )
        ) {
            return ActiveScanResult(target, 0, null, "Unsupported injection point for IDOR/BOLA")
        }
        val payloads =
            payloadGenerator.generateContextAwarePayloads(
                target.vulnHint.vulnClass,
                target.injectionPoint.originalValue,
                5,
            )
        if (payloads.isEmpty()) {
            return ActiveScanResult(target, 0, null, "No IDOR payloads available")
        }

        val baselineStatus = baseline.response()?.statusCode() ?: 0
        if (baselineStatus !in 200..299) {
            return ActiveScanResult(target, 0, null, "Baseline response not successful")
        }

        for ((index, payload) in payloads.withIndex().untilHalted()) {
            try {
                val modifiedRequest =
                    injectPayload(
                        target.originalRequest.request(),
                        target.injectionPoint,
                        payload.value,
                    )
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                val modifiedRequestResponse =
                    HttpRequestResponse.httpRequestResponse(
                        modifiedRequest,
                        response.response(),
                    )

                val confirmation =
                    analyzeIdor(
                        target,
                        baseline,
                        modifiedRequestResponse,
                        payload,
                    )

                if (confirmation != null && confirmation.confirmed) {
                    return ActiveScanResult(target, index + 1, confirmation)
                }

                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] IDOR test error: ${e.message}")
            }
        }

        return ActiveScanResult(target, payloads.size, null)
    }

    private fun analyzeIdor(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
    ): VulnConfirmation? {
        val baselineBody = baseline.response()?.bodyToString() ?: ""
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val baselineStatus = baseline.response()?.statusCode() ?: 0
        val modifiedStatus = modified.response()?.statusCode() ?: 0

        if (baselineStatus !in 200..299 || modifiedStatus !in 200..299) return null
        if (baselineBody.isBlank() || modifiedBody.isBlank()) return null
        if (baselineBody == modifiedBody) return null
        if (!containsIdToken(baselineBody, target.injectionPoint.originalValue)) return null
        if (!containsIdToken(modifiedBody, payload.value)) return null
        if (containsIdToken(modifiedBody, target.injectionPoint.originalValue)) return null
        if (isAuthError(modified)) return null

        val lengthDiff = abs(baselineBody.length - modifiedBody.length)
        val lengthDiffPercent = if (baselineBody.isNotEmpty()) lengthDiff.toDouble() / baselineBody.length else 1.0
        if (lengthDiffPercent > 0.2) return null

        val isJson = isJsonResponse(baseline, baselineBody) && isJsonResponse(modified, modifiedBody)
        val confidence =
            if (isJson) {
                val baselineKeys = extractJsonKeys(baselineBody)
                val modifiedKeys = extractJsonKeys(modifiedBody)
                val common = baselineKeys.intersect(modifiedKeys).size
                val union = baselineKeys.union(modifiedKeys).size
                val keyOverlap = if (union > 0) common.toDouble() / union else 0.0
                if (common < 5 || keyOverlap < 0.7) return null
                if (keyOverlap > 0.85) 95 else 90
            } else {
                val diff = responseAnalyzer.calculateDifference(baselineBody, modifiedBody)
                if (diff.similarity < 0.85) return null
                90
            }

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = modified,
            confidence = confidence,
            evidence = "IDOR/BOLA confirmed: ${target.injectionPoint.originalValue} -> ${payload.value} with similar response structure",
            confirmed = true,
        )
    }

    private fun executeAuthzBypassCheck(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
    ): VulnConfirmation? {
        val request = target.originalRequest.request()
        if (!hasAuthContext(request)) return null

        val strippedRequest = stripAuthHeaders(request)
        val response = sendRequestWithTimeout(strippedRequest) ?: return null
        val strippedRequestResponse =
            HttpRequestResponse.httpRequestResponse(
                strippedRequest,
                response.response(),
            )

        val baselineStatus = baseline.response()?.statusCode() ?: 0
        val strippedStatus = strippedRequestResponse.response()?.statusCode() ?: 0
        if (baselineStatus !in 200..299 || strippedStatus !in 200..299) return null
        if (isAuthError(strippedRequestResponse)) return null

        val baselineBody = baseline.response()?.bodyToString() ?: ""
        val strippedBody = strippedRequestResponse.response()?.bodyToString() ?: ""
        if (baselineBody.isBlank() || strippedBody.isBlank()) return null

        val diff = responseAnalyzer.calculateDifference(baselineBody, strippedBody)
        val lengthDiff = abs(baselineBody.length - strippedBody.length)
        val lengthDiffPercent = if (baselineBody.isNotEmpty()) lengthDiff.toDouble() / baselineBody.length else 1.0
        if (diff.similarity < 0.85 || lengthDiffPercent > 0.15) return null

        val payload =
            Payload(
                value = "(auth stripped)",
                vulnClass = target.vulnHint.vulnClass,
                detectionMethod = DetectionMethod.CONTENT_BASED,
                risk = PayloadRisk.SAFE,
                expectedEvidence = "Unauthenticated response matches baseline",
            )

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = strippedRequestResponse,
            confidence = 90,
            evidence = "Authorization bypass: unauthenticated response matched baseline (similarity ${(diff.similarity * 100).toInt()}%)",
            confirmed = true,
        )
    }

    private fun confirmCacheIssue(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
    ): VulnConfirmation? =
        when (target.vulnHint.vulnClass) {
            VulnClass.CACHE_POISONING -> confirmCachePoisoning(target, baseline, modified, payload)
            VulnClass.CACHE_DECEPTION -> confirmCacheDeception(target, modified, payload)
            else -> null
        }

    private fun confirmCachePoisoning(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        modified: HttpRequestResponse,
        payload: Payload,
    ): VulnConfirmation? {
        val modifiedFull = buildFullResponse(modified)
        if (!modifiedFull.contains(payload.value)) return null
        if (buildFullResponse(baseline).contains(payload.value)) return null
        if (!isCacheable(modified)) return null

        val followUpResponse = sendRequestWithTimeout(target.originalRequest.request()) ?: return null
        val followUp =
            HttpRequestResponse.httpRequestResponse(
                target.originalRequest.request(),
                followUpResponse.response(),
            )
        val followUpFull = buildFullResponse(followUp)
        if (!followUpFull.contains(payload.value)) return null
        if (!isCacheHit(followUp)) return null

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = baseline,
            exploitResponse = modified,
            confidence = 90,
            evidence = "Cache poisoning confirmed: marker persisted and cache hit detected",
            confirmed = true,
        )
    }

    private fun confirmCacheDeception(
        target: ActiveScanTarget,
        modified: HttpRequestResponse,
        payload: Payload,
    ): VulnConfirmation? {
        val modifiedBody = modified.response()?.bodyToString() ?: ""
        val path = modified.request().path()
        if (!staticAssetRegex.containsMatchIn(path)) return null
        if (!sensitiveDataRegex.containsMatchIn(modifiedBody)) return null
        if (!isCacheable(modified)) return null

        val followUpResponse = sendRequestWithTimeout(target.originalRequest.request()) ?: return null
        val followUp =
            HttpRequestResponse.httpRequestResponse(
                target.originalRequest.request(),
                followUpResponse.response(),
            )
        val followUpBody = followUp.response()?.bodyToString() ?: ""
        if (!sensitiveDataRegex.containsMatchIn(followUpBody)) return null
        if (!isCacheHit(followUp)) return null

        return VulnConfirmation(
            target = target,
            payload = payload,
            originalResponse = modified,
            exploitResponse = followUp,
            confidence = 90,
            evidence = "Cache deception confirmed: sensitive data served from cache on static-looking path",
            confirmed = true,
        )
    }

    private fun hasAuthContext(request: HttpRequest): Boolean {
        val hasAuthHeader =
            request.headers().any { header ->
                authHeaderNames.contains(header.name().lowercase())
            }
        val cookieHeader = request.headerValue("Cookie") ?: ""
        val hasAuthCookie = authCookieHint.containsMatchIn(cookieHeader)
        return hasAuthHeader || hasAuthCookie
    }

    private fun stripAuthHeaders(request: HttpRequest): HttpRequest {
        var stripped = request
        request.headers().forEach { header ->
            if (authHeaderNames.contains(header.name().lowercase())) {
                stripped = stripped.withRemovedHeader(header.name())
            }
        }
        stripped = stripped.withRemovedHeader("Cookie")
        return stripped
    }

    private fun isAuthError(response: HttpRequestResponse): Boolean {
        val status = response.response()?.statusCode()?.toInt() ?: 0
        if (status == 401 || status == 403) return true
        val location = responseHeaderValue(response, "Location")?.lowercase()
        if (location != null && (location.contains("login") || location.contains("signin"))) return true
        val wwwAuth = responseHeaderValue(response, "WWW-Authenticate")
        if (!wwwAuth.isNullOrBlank()) return true
        val body = response.response()?.bodyToString() ?: ""
        return authErrorRegex.containsMatchIn(body)
    }

    private fun isJsonResponse(
        response: HttpRequestResponse,
        body: String,
    ): Boolean {
        val contentType = responseHeaderValue(response, "Content-Type")?.lowercase() ?: ""
        if (contentType.contains("json")) return true
        val trimmed = body.trimStart()
        return trimmed.startsWith("{") || trimmed.startsWith("[")
    }

    private fun extractJsonKeys(body: String): Set<String> {
        val keys = mutableSetOf<String>()
        val pattern = Regex("\"([A-Za-z0-9_\\-]+)\"\\s*:")
        pattern.findAll(body).forEach { match ->
            keys.add(match.groupValues[1])
        }
        return keys
    }

    private fun containsIdToken(
        body: String,
        value: String,
    ): Boolean {
        val escaped = Regex.escape(value)
        val pattern = Regex("(?<![A-Za-z0-9])$escaped(?![A-Za-z0-9])")
        return pattern.containsMatchIn(body)
    }

    private fun buildFullResponse(response: HttpRequestResponse): String {
        val headers =
            response
                .response()
                ?.headers()
                ?.joinToString("\n") { "${it.name()}: ${it.value()}" }
                ?: ""
        val body = response.response()?.bodyToString() ?: ""
        return headers + "\n\n" + body
    }

    private fun isCacheable(response: HttpRequestResponse): Boolean {
        val cacheControl = responseHeaderValue(response, "Cache-Control")?.lowercase() ?: return false
        if (cacheControl.contains("no-store") || cacheControl.contains("no-cache") || cacheControl.contains("private")) {
            return false
        }
        return cacheControl.contains("max-age") || cacheControl.contains("s-maxage") || cacheControl.contains("public")
    }

    private fun isCacheHit(response: HttpRequestResponse): Boolean {
        val xCache = responseHeaderValue(response, "X-Cache")?.lowercase()
        if (xCache != null && xCache.contains("hit")) return true
        val cfCache = responseHeaderValue(response, "CF-Cache-Status")?.lowercase()
        if (cfCache != null && cfCache.contains("hit")) return true
        val age = responseHeaderValue(response, "Age")?.toIntOrNull()
        return age != null && age > 0
    }

    private fun responseHeaderValue(
        response: HttpRequestResponse,
        name: String,
    ): String? =
        response
            .response()
            ?.headers()
            ?.firstOrNull { it.name().equals(name, ignoreCase = true) }
            ?.value()

    private fun registerSsrfoob(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
        settings: AgentSettings,
    ) {
        if (!useCollaborator) return
        if (settings.privacyMode != PrivacyMode.OFF) return
        if (target.injectionPoint.type !in
            setOf(
                InjectionType.URL_PARAM,
                InjectionType.BODY_PARAM,
                InjectionType.JSON_FIELD,
                InjectionType.HEADER,
                InjectionType.PATH_SEGMENT,
            )
        ) {
            return
        }

        val client = obtainCollaboratorClient() ?: return

        val collaboratorPayload =
            try {
                client.generatePayload()
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Collaborator payload error: ${e.message}")
                return
            }

        val oastUrl = "http://$collaboratorPayload"
        val oastRequest =
            injectPayload(
                target.originalRequest.request(),
                target.injectionPoint,
                oastUrl,
            )
        val oastResponse = sendRequestWithTimeout(oastRequest) ?: return
        val oastRequestResponse = HttpRequestResponse.httpRequestResponse(oastRequest, oastResponse.response())

        // Register the payload; the shared poller matches interactions against it and creates the
        // confirmed issue asynchronously, so no scanner thread blocks waiting for an interaction.
        pendingOast[collaboratorPayload.id().toString()] =
            PendingOast(
                target = target,
                baseline = baseline,
                exploitRequestResponse = oastRequestResponse,
                oastUrl = oastUrl,
                registeredAtMs = System.currentTimeMillis(),
            )
    }

    private fun obtainCollaboratorClient(): CollaboratorClient? {
        oastLock.lock()
        try {
            collaboratorClient?.let { return it }
            val client =
                try {
                    api.collaborator().createClient()
                } catch (e: Exception) {
                    api.logging().logToError("[ActiveAiScanner] Collaborator unavailable: ${e.message}")
                    return null
                }
            collaboratorClient = client
            return client
        } finally {
            oastLock.unlock()
        }
    }

    private fun pollOastInteractions() {
        val client = collaboratorClient ?: return
        if (pendingOast.isEmpty()) return
        val interactions =
            try {
                client.getAllInteractions()
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] Collaborator poll error: ${e.message}")
                return
            }
        for (interaction in interactions) {
            val pending = pendingOast.remove(interaction.id().toString()) ?: continue
            val payload =
                Payload(
                    value = pending.oastUrl,
                    vulnClass = VulnClass.SSRF,
                    detectionMethod = DetectionMethod.OUT_OF_BAND,
                    risk = PayloadRisk.SAFE,
                    expectedEvidence = "Collaborator interaction",
                )
            confirmFinding(
                VulnConfirmation(
                    target = pending.target,
                    payload = payload,
                    originalResponse = pending.baseline,
                    exploitResponse = pending.exploitRequestResponse,
                    confidence = 95,
                    evidence = "Collaborator interaction received (${interaction.type()}) for ${pending.oastUrl}",
                    confirmed = true,
                ),
            )
        }
        expireStaleOast()
    }

    private fun expireStaleOast() {
        if (pendingOast.isEmpty()) return
        val ttlMs = maxOf(300_000L, timeoutSeconds.toLong() * 1000L)
        val now = System.currentTimeMillis()
        pendingOast.entries.removeIf { now - it.value.registeredAtMs > ttlMs }
    }

    private fun sendRequestWithTimeout(request: HttpRequest): HttpRequestResponse? {
        val timeout = timeoutSeconds.coerceAtLeast(5).toLong()
        // REL-07 / SC6: the submit lives INSIDE the try, and the handle is a nullable local so the
        // existing arms can still cancel it. requestExecutor is bounded with an abort policy, so a
        // saturated pool throws right here; submitted above the try that throw would escape this
        // function, climb through executeScan into the per-target catch, and abort a whole target
        // with a message of `null` — the exception type usually carries none.
        // Phase 33 / D-02: a worker that OFF interrupted sends nothing new to the target.
        if (Thread.currentThread().isInterrupted) return null
        var future: Future<HttpRequestResponse>? = null
        return try {
            future =
                requestExecutor.submit(
                    Callable {
                        api.http().sendRequest(request)
                    },
                )
            future.get(timeout, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            future?.cancel(true)
            api.logging().logToError("[ActiveAiScanner] Request timeout after ${timeout}s for ${request.url().take(80)}")
            null
        } catch (_: RejectedExecutionException) {
            api.logging().logToError("[ActiveAiScanner] Request rejected — scan request pool saturated for ${request.url().take(80)}")
            null
        } catch (_: InterruptedException) {
            // Phase 33 / D-02: OFF interrupted the wait. A request already on the wire may still finish;
            // the caller's `?: continue` reaches its loop head, which now leaves the loop.
            future?.cancel(true)
            Thread.currentThread().interrupt()
            null
        } catch (e: Exception) {
            future?.cancel(true)
            api.logging().logToError("[ActiveAiScanner] Request error: ${e.message}")
            null
        }
    }

    private fun handleResult(result: ActiveScanResult) {
        val confirmation = result.confirmation
        if (confirmation != null && confirmation.confirmed) {
            confirmFinding(confirmation)
        }
    }

    // Shared by the synchronous scan path and the async OOB poller: record a confirmed finding
    // (issue creation + adaptive-payload tech hints + audit).
    private fun confirmFinding(confirmation: VulnConfirmation) {
        vulnsConfirmed.incrementAndGet()
        createConfirmedIssue(confirmation)

        // Record error patterns as tech hints for adaptive payloads
        val host =
            runCatching {
                java.net
                    .URI(
                        confirmation.target.originalRequest
                            .request()
                            .url(),
                    ).host
                    .orEmpty()
            }.getOrDefault("")
        if (host.isNotBlank()) {
            val evidence = confirmation.evidence.lowercase()
            val dbHints = mutableSetOf<String>()
            if (evidence.contains("mysql") || evidence.contains("mariadb")) dbHints.add("MySQL")
            if (evidence.contains("postgresql") || evidence.contains("pg_query")) dbHints.add("PostgreSQL")
            if (evidence.contains("mssql") || evidence.contains("sql server")) dbHints.add("MSSQL")
            if (evidence.contains("oracle") || evidence.contains("ora-")) dbHints.add("Oracle")
            if (evidence.contains("sqlite")) dbHints.add("SQLite")
            if (dbHints.isNotEmpty()) ScanKnowledgeBase.recordTechStack(host, dbHints)
            ScanKnowledgeBase.recordErrorPattern(host, confirmation.evidence.take(100))
        }

        audit.logEvent(
            "active_scan_confirmed",
            mapOf(
                "vuln_class" to confirmation.target.vulnHint.vulnClass.name,
                "url" to
                    AuditLogger.endpointOf(
                        confirmation.target.originalRequest
                            .request()
                            .url(),
                    ),
                "confidence" to confirmation.confidence.toString(),
            ) + audit.bodyFields("payload", confirmation.payload.value),
        )
    }

    private fun createConfirmedIssue(confirmation: VulnConfirmation) {
        val target = confirmation.target
        val payload = confirmation.payload

        val title = "[AI Active] ${target.vulnHint.vulnClass.name}"

        // Get backend info for metadata
        val backendInfo = supervisor.getCurrentBackendInfo()
        val metadataSection =
            buildMetadataSectionPlain(backendInfo, "Active", confirmation.confidence, "Confirmed via AI active exploitation testing.")

        // (PRIV-05) 28-01 / AR-27-08: these lines are built by the SINGLE producer in
        // ScannerIssueSupport, never inline here. A second producer is how the cookie control on
        // this carrier gets bypassed without anyone editing it.
        val detailLines =
            ScannerIssueSupport.buildActiveIssueDetailLines(
                target.injectionPoint,
                target.vulnHint.vulnClass.name,
                payload,
                confirmation.evidence,
                metadataSection,
                RedactionPolicy.fromMode(getSettings().privacyMode),
            )
        val detail = IssueUtils.formatIssueDetailHtml(detailLines)

        val severity = ScannerIssueSupport.mapSeverity(target.vulnHint.vulnClass)
        val confidence =
            when {
                confirmation.confidence >= 95 -> AuditIssueConfidence.CERTAIN
                confirmation.confidence >= 80 -> AuditIssueConfidence.FIRM
                else -> AuditIssueConfidence.TENTATIVE
            }

        try {
            issueLock.lock()
            try {
                if (hasExistingIssue(title, target.originalRequest.request().url())) {
                    api.logging().logToOutput("[ActiveAiScanner] Consolidated duplicate issue: $title")
                    return
                }
                // Add markers to highlight payload in request and evidence in response
                val markedExploit =
                    IssueMarkerSupport
                        .markRequestPayload(
                            confirmation.exploitResponse,
                            payload.value,
                        ).let { IssueMarkerSupport.markResponseEvidence(it, confirmation.evidence) }

                val issue =
                    AuditIssue.auditIssue(
                        title,
                        detail,
                        ScannerIssueSupport.remediation(target.vulnHint.vulnClass),
                        target.originalRequest.request().url(),
                        severity,
                        confidence,
                        null,
                        null,
                        severity,
                        listOf(target.originalRequest, markedExploit),
                    )

                api.siteMap().add(issue)
            } finally {
                issueLock.unlock()
            }
            api.logging().logToOutput(
                "[ActiveAiScanner] CONFIRMED: ${target.vulnHint.vulnClass.name} in " +
                    "'${target.injectionPoint.name}' (${confirmation.confidence}%)",
            )

            // Record in knowledge base
            ScanKnowledgeBase.recordVulnSignal(
                ScanKnowledgeBase.VulnSignal(
                    endpoint = target.originalRequest.request().url(),
                    vulnClass = target.vulnHint.vulnClass.name,
                    severity = ScannerIssueSupport.mapSeverity(target.vulnHint.vulnClass).name,
                    confidence = confirmation.confidence,
                    source = "active",
                    evidence = confirmation.evidence.take(200),
                ),
            )

            val finding =
                ActiveAiFinding(
                    timestamp = System.currentTimeMillis(),
                    url = target.originalRequest.request().url(),
                    title = title,
                    severity = ScannerIssueSupport.mapSeverity(target.vulnHint.vulnClass).name,
                    detail = confirmation.evidence,
                    confidence = confirmation.confidence,
                )
            synchronized(confirmations) {
                if (confirmations.size >= Defaults.FINDINGS_BUFFER_SIZE) confirmations.removeFirst()
                confirmations.addLast(finding)
            }
        } catch (e: Exception) {
            api.logging().logToError("[ActiveAiScanner] Failed to create issue: ${e.message}")
        }
    }

    private fun buildMetadataSectionPlain(
        backendInfo: AgentSupervisor.BackendInfo?,
        scanType: String,
        confidence: Int,
        note: String,
    ): String {
        val lines = mutableListOf<String>()
        lines.add("AI Analysis Metadata")
        if (backendInfo != null) {
            lines.add("  Backend: ${backendInfo.displayName}")
            if (backendInfo.model != null) {
                lines.add("  Model: ${backendInfo.model}")
            }
        } else {
            lines.add("  Backend: Unknown")
        }
        lines.add("  Scan Type: $scanType")
        lines.add("  Confidence: $confidence%")

        val timestamp =
            java.time.Instant
                .now()
                .toString()
                .replace('T', ' ')
                .substringBefore('.')
        lines.add("  Scan Date: $timestamp UTC")
        lines.add("  Note: $note")
        return lines.joinToString("\r\n")
    }

    private fun hasExistingIssue(
        name: String,
        baseUrl: String,
    ): Boolean =
        IssueUtils.hasEquivalentIssue(
            name = name,
            baseUrl = baseUrl,
            issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() },
        )

    private fun injectPayload(
        request: HttpRequest,
        point: InjectionPoint,
        payload: String,
    ): HttpRequest =
        when (point.type) {
            InjectionType.URL_PARAM -> {
                val url = request.url()
                val newUrl =
                    url
                        .replace(
                            "${point.name}=${java.net.URLEncoder.encode(point.originalValue, "UTF-8")}",
                            "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}",
                        ).replace(
                            "${point.name}=${point.originalValue}",
                            "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}",
                        )
                request
                    .withPath(newUrl.substringAfter(request.httpService().host()).substringBefore("?").ifEmpty { "/" })
                    .let { req ->
                        val query = newUrl.substringAfter("?", "")
                        if (query.isNotEmpty()) {
                            HttpRequest.httpRequest(
                                req.httpService(),
                                "${req.method()} ${req.path()}?$query ${req.httpVersion()}\r\n${req.headers().joinToString(
                                    "\r\n",
                                ) { "${it.name()}: ${it.value()}" }}\r\n\r\n${req.bodyToString()}",
                            )
                        } else {
                            req
                        }
                    }
            }
            InjectionType.BODY_PARAM -> {
                val body = request.bodyToString()
                val newBody =
                    body.replace(
                        "${point.name}=${point.originalValue}",
                        "${point.name}=${java.net.URLEncoder.encode(payload, "UTF-8")}",
                    )
                request.withBody(newBody)
            }
            InjectionType.HEADER -> {
                request
                    .withRemovedHeader(point.name)
                    .withAddedHeader(point.name, payload)
            }
            InjectionType.COOKIE -> {
                val cookies = request.headerValue("Cookie") ?: ""
                val newCookies =
                    cookies.replace(
                        "${point.name}=${point.originalValue}",
                        "${point.name}=$payload",
                    )
                request.withRemovedHeader("Cookie").withAddedHeader("Cookie", newCookies)
            }
            InjectionType.PATH_SEGMENT -> {
                val path = request.path()
                val newPath = path.replace(point.originalValue, payload)
                request.withPath(newPath)
            }
            InjectionType.JSON_FIELD -> {
                val body = request.bodyToString()
                val numericPattern = Regex("-?\\d+(?:\\.\\d+)?")
                val isNumericOriginal = numericPattern.matches(point.originalValue)
                val isNumericPayload = numericPattern.matches(payload)
                val replacementValue = if (isNumericOriginal && isNumericPayload) payload else "\"$payload\""
                val fieldPattern =
                    Regex(
                        "\"${Regex.escape(point.name)}\"\\s*:\\s*\"?${Regex.escape(point.originalValue)}\"?",
                    )
                val newBody =
                    fieldPattern.replace(
                        body,
                        "\"${point.name}\":$replacementValue",
                    )
                request.withBody(newBody)
            }
            InjectionType.XML_ELEMENT -> {
                val body = request.bodyToString()
                val newBody =
                    body.replace(
                        "<${point.name}>${point.originalValue}</${point.name}>",
                        "<${point.name}>$payload</${point.name}>",
                    )
                request.withBody(newBody)
            }
        }

    // ==================== 403 BYPASS ====================

    private val minBypassBodyDelta = 50 // minimum body length difference to consider bypass meaningful

    private val bypassHeaders =
        listOf(
            "X-Forwarded-For" to "127.0.0.1",
            "X-Real-IP" to "127.0.0.1",
            "X-Originating-IP" to "127.0.0.1",
            "X-Remote-IP" to "127.0.0.1",
            "X-Remote-Addr" to "127.0.0.1",
            "X-Client-IP" to "127.0.0.1",
            "X-Forwarded-Host" to "127.0.0.1",
            "X-Original-URL" to "/",
            "X-Rewrite-URL" to "/",
        )

    /**
     * Attempt to bypass 403 responses using:
     * 1. IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
     * 2. Path manipulation (/path/ , /path/., /path/..;/path, etc.)
     * 3. HTTP method switching: only GET and HEAD below DANGEROUS; POST and PUT are tried only at
     *    DANGEROUS (ScanPolicy.methodSwitchAlternatives, quick 261008-vau)
     */
    private fun execute403Bypass(
        target: ActiveScanTarget,
        baseline: HttpRequestResponse,
    ): ActiveScanResult {
        val baselineStatus = baseline.response()?.statusCode()?.toInt() ?: 0
        if (baselineStatus != 403) {
            return ActiveScanResult(target, 0, null, "Baseline is not 403")
        }

        val request = target.originalRequest.request()
        val path = request.path()
        var attemptCount = 0

        // === Technique 1: IP spoofing headers ===
        val baselineBodyLen = baseline.response()?.body()?.length() ?: 0
        for ((headerName, headerValue) in bypassHeaders.untilHalted()) {
            try {
                val modifiedRequest = request.withAddedHeader(headerName, headerValue)
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                attemptCount++

                val status = response.response()?.statusCode()?.toInt() ?: 0
                // Only accept 2xx as potential bypass; redirects (301/302) are not evidence of access
                if (status in 200..299) {
                    val modifiedRR = HttpRequestResponse.httpRequestResponse(modifiedRequest, response.response())
                    // Reject auth errors (login pages, WWW-Authenticate, etc.)
                    if (isAuthError(modifiedRR)) continue
                    // Require meaningful body length difference from baseline
                    val responseBodyLen = response.response()?.body()?.length() ?: 0
                    val lenDelta = kotlin.math.abs(responseBodyLen - baselineBodyLen)
                    if (lenDelta < minBypassBodyDelta) continue

                    val payload =
                        Payload(
                            value = "$headerName: $headerValue",
                            vulnClass = VulnClass.ACCESS_CONTROL_BYPASS,
                            detectionMethod = DetectionMethod.CONTENT_BASED,
                            risk = PayloadRisk.SAFE,
                            expectedEvidence = "403 bypassed with header",
                        )
                    return ActiveScanResult(
                        target,
                        attemptCount,
                        VulnConfirmation(
                            target = target,
                            payload = payload,
                            originalResponse = baseline,
                            exploitResponse = modifiedRR,
                            confidence = 75,
                            evidence = "403 bypass via $headerName header: 403 -> $status (body delta: $lenDelta bytes)",
                            confirmed = true,
                        ),
                    )
                }
                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] 403 bypass header error: ${e.message}")
            }
        }

        // === Technique 2: Path manipulation ===
        val pathVariations = buildPathVariations(path)
        for (variation in pathVariations.untilHalted()) {
            try {
                val modifiedRequest = request.withPath(variation)
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                attemptCount++

                val status = response.response()?.statusCode()?.toInt() ?: 0
                if (status in 200..299) {
                    // Verify the response is not just a generic page (e.g., 200 but login redirect)
                    val modifiedRR = HttpRequestResponse.httpRequestResponse(modifiedRequest, response.response())
                    if (isAuthError(modifiedRR)) continue
                    // Require meaningful body length difference from baseline
                    val responseBodyLen = response.response()?.body()?.length() ?: 0
                    val lenDelta = kotlin.math.abs(responseBodyLen - baselineBodyLen)
                    if (lenDelta < minBypassBodyDelta) continue

                    val payload =
                        Payload(
                            value = variation,
                            vulnClass = VulnClass.ACCESS_CONTROL_BYPASS,
                            detectionMethod = DetectionMethod.CONTENT_BASED,
                            risk = PayloadRisk.SAFE,
                            expectedEvidence = "403 bypassed with path variation",
                        )
                    return ActiveScanResult(
                        target,
                        attemptCount,
                        VulnConfirmation(
                            target = target,
                            payload = payload,
                            originalResponse = baseline,
                            exploitResponse = modifiedRR,
                            confidence = 90,
                            evidence =
                                "403 bypass via path manipulation: $path -> $variation " +
                                    "(403 -> $status, body delta: $lenDelta bytes)",
                            confirmed = true,
                        ),
                    )
                }
                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] 403 bypass path error: ${e.message}")
            }
        }

        // === Technique 3: HTTP method switching ===
        val alternativeMethods = ScanPolicy.methodSwitchAlternatives(request.method(), maxRiskLevel)
        for (method in alternativeMethods.untilHalted()) {
            try {
                val modifiedRequest = request.withMethod(method)
                val response = sendRequestWithTimeout(modifiedRequest) ?: continue
                attemptCount++

                val status = response.response()?.statusCode()?.toInt() ?: 0
                if (status in 200..299) {
                    val modifiedRR = HttpRequestResponse.httpRequestResponse(modifiedRequest, response.response())
                    if (isAuthError(modifiedRR)) continue
                    // Require meaningful body length difference from baseline
                    val responseBodyLen = response.response()?.body()?.length() ?: 0
                    val lenDelta = kotlin.math.abs(responseBodyLen - baselineBodyLen)
                    if (lenDelta < minBypassBodyDelta) continue

                    val payload =
                        Payload(
                            value = method,
                            vulnClass = VulnClass.ACCESS_CONTROL_BYPASS,
                            detectionMethod = DetectionMethod.CONTENT_BASED,
                            risk = PayloadRisk.SAFE,
                            expectedEvidence = "403 bypassed with method switch",
                        )
                    return ActiveScanResult(
                        target,
                        attemptCount,
                        VulnConfirmation(
                            target = target,
                            payload = payload,
                            originalResponse = baseline,
                            exploitResponse = modifiedRR,
                            confidence = 85,
                            evidence =
                                "403 bypass via method switch: ${request.method()} -> $method " +
                                    "(403 -> $status, body delta: $lenDelta bytes)",
                            confirmed = true,
                        ),
                    )
                }
                Thread.sleep(requestDelayMs)
            } catch (_: InterruptedException) {
                // Phase 33 / D-02: OFF interrupted this worker; keep the flag and stop attacking.
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                api.logging().logToError("[ActiveAiScanner] 403 bypass method error: ${e.message}")
            }
        }

        return ActiveScanResult(target, attemptCount, null)
    }

    private fun buildPathVariations(path: String): List<String> {
        val variations = mutableListOf<String>()
        val cleanPath = path.substringBefore("?")
        val query = if (path.contains("?")) "?" + path.substringAfter("?") else ""

        // Trailing slash
        if (!cleanPath.endsWith("/")) {
            variations.add("$cleanPath/$query")
        }
        // Trailing dot
        variations.add("$cleanPath/.$query")
        // Double slash prefix
        variations.add("/$cleanPath$query")
        // Path traversal bypass
        variations.add("$cleanPath/..;$cleanPath$query")
        // URL-encoded space
        variations.add("$cleanPath%20$query")
        // Case variation on last segment
        val segments = cleanPath.split("/")
        if (segments.size >= 2) {
            val lastSegment = segments.last()
            if (lastSegment.isNotBlank() && lastSegment.any { it.isLetter() }) {
                val caseSwapped =
                    lastSegment
                        .mapIndexed { i, c ->
                            if (i == 0 && c.isLowerCase()) {
                                c.uppercaseChar()
                            } else if (i == 0 && c.isUpperCase()) {
                                c.lowercaseChar()
                            } else {
                                c
                            }
                        }.joinToString("")
                variations.add((segments.dropLast(1) + caseSwapped).joinToString("/") + query)
            }
        }
        // .json suffix
        if (!cleanPath.endsWith(".json")) {
            variations.add("$cleanPath.json$query")
        }
        // Semicolon suffix
        variations.add("$cleanPath;$query")

        return variations.distinct()
    }

    private fun extractInjectionPoints(requestResponse: HttpRequestResponse): List<InjectionPoint> = InjectionPointExtractor.extract(requestResponse.request(), headerInjectionAllowlist)

    /** Unload with a fresh shared deadline; see the overload. */
    fun shutdown() = shutdown(ShutdownDeadline.unload())

    /**
     * Phase 33 / D-05 — stops the scanner for good within the shared unload [deadline].
     *
     * Nothing starts again afterwards ([setEnabled] and [requestEnabled] become no-ops). The worker and
     * scheduler pools are interrupted and awaited only for what is left of [deadline]; one that does not
     * stop is forced and reported with one Error line. The per-request pool is `shutdownNow()`'d but NOT
     * awaited: a Montoya request in flight cannot be interrupted, and the final unload sweep waits for it
     * once. Queued lifecycle requests still run (they can no longer start anything) so their callbacks
     * fire.
     */
    fun shutdown(deadline: ShutdownDeadline) {
        terminated = true
        enabled.set(false)
        val logError: (String) -> Unit = { line -> runCatching { api.logging().logToError(line) } }
        val workers = executor
        val scheduler = scheduledExecutor
        withLifecycleLockWithin(deadline) { stopProcessing(waitForWorkers = false) }
        workers?.let { deadline.awaitOrForce(it, "Active scanner workers", logError) }
        scheduler?.let { deadline.awaitOrForce(it, "Active scanner scheduler", logError) }
        requestExecutor.shutdownNow()
        lifecycle.shutdown()
        deadline.awaitOrForce(lifecycle, "Active scanner lifecycle", logError)
        listOfNotNull(workers, scheduler, lifecycle).forEach { ExtensionThreads.release(it) }
    }

    /**
     * Runs [block] holding [lifecycleLock] when it can be taken before [deadline]; otherwise runs it
     * anyway. At unload a toggle stop that still holds the lock must not eat the whole budget, and every
     * step of the disable transition is safe to repeat.
     */
    private fun withLifecycleLockWithin(
        deadline: ShutdownDeadline,
        block: () -> Unit,
    ) {
        val locked =
            try {
                lifecycleLock.tryLock(deadline.remainingMs(), TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
        try {
            block()
        } finally {
            if (locked) lifecycleLock.unlock()
        }
    }

    /** The live worker pool, or null while the scanner is stopped. Tests only. */
    internal fun workerPoolForTests(): ThreadPoolExecutor? = executor as? ThreadPoolExecutor

    /** How many shared baselines are cached. Tests only. */
    internal fun baselineCacheSizeForTests(): Int = baselineCache.size()

    /** How many Collaborator confirmations are pending. Tests only. */
    internal fun pendingOastCountForTests(): Int = pendingOast.size
}

/**
 * REL-07 / SC6 — the thread factory for the active scanner's per-request pool.
 *
 * Every thread it produces is a daemon and carries a counter-suffixed, product-prefixed kebab-case
 * name, so a Burp thread dump taken during a scan against an unresponsive host says which subsystem
 * owns the stuck threads instead of showing an anonymous `pool-N-thread-M`. That readability is the
 * stated point of SC6; an unnamed bounded pool would satisfy the ceiling and none of the diagnosis.
 *
 * Phase 33 / D-11: the thread helper builds the threads (`ExtensionThreads.factory("scan-request")`), the
 * same factory the live pool gets from `ExtensionThreads.boundedPool("scan-request", ...)`. The counter
 * is per factory instance, so each pool numbers its own threads from 1.
 *
 * Visibility: `internal` so `ScanRequestExecutorTest` can assert on the names and the daemon flag by
 * calling this directly, with no live pool and no reflection (same pattern as `buildTimeoutMessage`
 * / `CliTimeoutMessageTest`). Not part of the scanner's public surface.
 */
internal fun scanRequestThreadFactory(): ThreadFactory = ExtensionThreads.factory("scan-request")
