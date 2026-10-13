package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * REL-06 / SC2 (plus the SC1 x SC6 coupling) — per-target fault isolation in [ActiveAiScanner].
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml:47` passes. `ActiveScannerFailureIsolationTest`
 * is the approved name; the natural `ActiveScannerBackpressureTest` and
 * `ActiveScannerConcurrencyTest` forms both end in an excluded suffix and would have made this suite
 * silently stop running on the PR gate.
 *
 * **What is actually red here, stated so nobody over-claims it.** SC2's first clause — "the scanner
 * keeps processing its queue after an induced failure on one target" — is already TRUE in the
 * pre-fix code, because the per-target `try/catch/finally` inside `processQueue` predates this
 * phase. An assertion on that clause alone passes both before and after the fix and therefore
 * proves nothing. The assertion that genuinely goes red pre-fix is the log-content one
 * (`theFailureLogLineNamesTheTargetItFailedOn`): the old message was
 * `[ActiveAiScanner] Error: <exception message>` and carried no target identifier at all. The two
 * are asserted as a pair; only the second is a gate.
 *
 * **The fault-injection lever is the constructor's `getSettings` lambda, scoped to scan worker
 * threads.** On a scan worker it is called at exactly one place — the first line of `executeScan`.
 * Since Phase 31 / D-02 `queueTarget` (the AI-gate pre-check) and `getStatus` (the paused state) also
 * read it, on the caller's thread, so the lever only throws when [onScanWorker] is true. No new
 * production seam was added for this suite.
 *
 * **No test here compares an elapsed duration to a threshold.** Progress is awaited by polling a
 * monotone counter inside [assertTimeoutPreemptively], whose failure mode is a categorical timeout
 * rather than a wall-clock comparison.
 *
 * **Every test that calls `setEnabled(true)` leaks a live scanner unless it is shut down.** The
 * `@AfterEach` below does that for all of them; `ActiveScannerDedupTest` does not, and that part of
 * it is deliberately not copied.
 *
 * **Reflection here touches this project's own class only** (`ActiveAiScanner`'s private `executor`
 * field and its private `processQueue` method). Nothing reflects into a JDK platform module, which
 * on JDK 21 would raise `InaccessibleObjectException` under this build's `--add-opens`-free test
 * JVM — the same fail-open trap `24-VALIDATION.md` rules out for the `deleteOnExit` probe.
 */
class ActiveScannerFailureIsolationTest {
    private val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    private var scanner: ActiveAiScanner? = null

    @AfterEach
    fun shutDownAnyLiveScanner() {
        scanner?.shutdown()
        scanner = null
    }

    /**
     * REL-06-F (SC2, isolation half) — one target blowing up in `executeScan` does not stop the
     * queue from draining.
     *
     * NOT a gate on its own: this passes against the pre-fix source too. It is asserted because SC2
     * names the behaviour and a regression here would be silent otherwise.
     *
     * `scansCompleted` is incremented in the per-target `finally`, on the success path and the
     * failure path alike, which is what makes completion countable without depending on a mock HTTP
     * round trip finishing.
     */
    @Test
    fun aTargetThatFailsMidScanDoesNotStopTheQueueFromDraining() {
        val invocations = AtomicInteger(0)
        val live =
            newScanner {
                if (onScanWorker() && invocations.incrementAndGet() == 1) error("induced settings failure on the first target scanned")
                TestSettings.baselineSettings()
            }
        live.setEnabled(true)

        (1..TARGET_COUNT).forEach { live.queueTarget(target(it)) }

        assertTimeoutPreemptively(Duration.ofSeconds(SETTLE_TIMEOUT_SECONDS)) {
            awaitScansCompleted(live, TARGET_COUNT)
        }
        live.setEnabled(false)

        assertEquals(
            TARGET_COUNT,
            live.getStatus().scansCompleted,
            "REL-06 / SC2 isolation: all $TARGET_COUNT queued targets must reach the per-target `finally`, " +
                "even though the first one to call `getSettings` threw. A lower count means one target's " +
                "failure escaped the per-target try/catch in `processQueue` and took the rest of the batch " +
                "down with it.",
        )
        assertEquals(
            0,
            live.getStatus().queueSize,
            "REL-06 / SC2 isolation: the queue must be fully drained. A non-zero size means the drain " +
                "stopped part-way through the batch after the induced failure.",
        )
    }

    /**
     * REL-06-G (SC2, log-content half) — **this is the gate.** The failure line must name the
     * target it failed on.
     *
     * `ActiveScanTarget.id` is URL plus injection-point name plus vulnerability class, so a single
     * containment assertion covers all three identifiers SC2 asks for.
     */
    @Test
    fun theFailureLogLineNamesTheTargetItFailedOn() {
        val live = newScanner { if (onScanWorker()) error("induced settings failure") else TestSettings.baselineSettings() }
        live.setEnabled(true)

        val failing = target(FAILING_TARGET_ID)
        live.queueTarget(failing)

        assertTimeoutPreemptively(Duration.ofSeconds(SETTLE_TIMEOUT_SECONDS)) {
            awaitScansCompleted(live, 1)
        }
        live.setEnabled(false)

        val errorLines = argumentCaptor<String>()
        verify(api.logging(), atLeastOnce()).logToError(errorLines.capture())
        val logged = errorLines.allValues

        assertTrue(
            logged.any { it.contains(failing.id) },
            "REL-06 / SC2 log-content gate: the per-target failure line must carry `target.id` — the URL, " +
                "the injection point name and the vulnerability class. Without it a failed scan is an " +
                "unattributable line in Burp's error log and the operator cannot tell WHICH target broke, " +
                "which is the whole deliverable of SC2's second clause. Expected a line containing " +
                "`${failing.id}`.\nActual error lines: $logged",
        )
        assertTrue(
            logged.all { it.startsWith(LOG_PREFIX) },
            "Every line this class writes to Burp's error log must keep the `$LOG_PREFIX` prefix, which is " +
                "how an operator filters scanner noise out of a shared error log (CONVENTIONS.md " +
                "§Error Handling).\nActual error lines: $logged",
        )
    }

    /**
     * REL-06-E (the SC1 x SC6 coupling) — a rejected `submit` on the scheduler thread does not end
     * the 500 ms queue-drain ticker.
     *
     * `processQueue`'s `exec.submit { … }` sits OUTSIDE any try, so once the scan worker pool is
     * bounded (SC6) a saturated pool throws `RejectedExecutionException` right there, on the
     * scheduler thread. A recurring JDK schedule whose task throws is cancelled for the rest of the
     * process — silently. This asserts that plan 24-01's `scheduleGuarded` absorbs it and the next
     * tick still attempts a submit.
     */
    @Test
    fun aRejectedSubmitOnTheSchedulerThreadDoesNotEndTheQueueDrainTicker() {
        val live = newScanner { TestSettings.baselineSettings() }
        live.setEnabled(true)

        val attempts = AtomicInteger(0)
        val executorField = ActiveAiScanner::class.java.getDeclaredField(EXECUTOR_FIELD)
        executorField.isAccessible = true
        executorField.set(live, RejectingExecutorService(attempts))

        (1..TICKER_TARGET_COUNT).forEach { live.queueTarget(target(it)) }

        assertTimeoutPreemptively(Duration.ofSeconds(TICKER_TIMEOUT_SECONDS)) {
            while (attempts.get() < MIN_SUBMIT_ATTEMPTS) {
                Thread.sleep(POLL_INTERVAL_MS)
            }
        }
        live.setEnabled(false)

        assertTrue(
            attempts.get() >= MIN_SUBMIT_ATTEMPTS,
            "REL-06 / SC1 x SC6: the queue-drain ticker must still be alive after its first submit was " +
                "rejected, so at least $MIN_SUBMIT_ATTEMPTS submit attempts must be recorded across " +
                "separate ticks. Exactly one attempt means the first `RejectedExecutionException` escaped " +
                "`scheduleGuarded` and the JDK cancelled the recurring schedule — after which the scanner " +
                "accepts targets forever and scans none of them, with nothing in the error log. Attempts: " +
                "${attempts.get()}",
        )
    }

    /**
     * A-EDGE-2 (empty case) — a tick with nothing queued is a no-op: no error logged, no scan
     * counted.
     *
     * Driven by invoking the private `processQueue` directly rather than by waiting on the ticker,
     * so the assertion is deterministic instead of sleeping for some number of 500 ms periods.
     */
    @Test
    fun aTickOverAnEmptyQueueLogsNothingAndCompletesNoScans() {
        val live = newScanner { TestSettings.baselineSettings() }
        live.setEnabled(true)

        val processQueue = ActiveAiScanner::class.java.getDeclaredMethod(PROCESS_QUEUE_METHOD)
        processQueue.isAccessible = true
        repeat(EMPTY_TICKS) { processQueue.invoke(live) }
        live.setEnabled(false)

        assertEquals(
            0,
            live.getStatus().scansCompleted,
            "An empty-queue tick must not count a scan. A non-zero count means `processQueue` submitted " +
                "work for a target it never polled.",
        )
        assertEquals(
            0,
            live.getStatus().queueSize,
            "The queue was never populated in this test, so it must still be empty.",
        )
        verify(api.logging(), never()).logToError(any<String>())
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /**
     * A headless [ActiveAiScanner] over a deep-stub Montoya mock, registered for `@AfterEach`
     * shutdown. [getSettings] is the fault-injection lever.
     *
     * `requestDelayMs` and `maxPayloadsPerPoint` are pinned to their smallest useful values so a
     * target that does NOT fail still finishes promptly; no assertion in this suite depends on how
     * long that takes.
     */
    private fun newScanner(getSettings: () -> AgentSettings): ActiveAiScanner {
        val created =
            ActiveAiScanner(
                api = api,
                supervisor = mock<AgentSupervisor>(),
                audit = mock<AuditLogger>(),
                getSettings = getSettings,
            )
        created.scopeOnly = false
        created.scanMode = ScanMode.FULL
        created.requestDelayMs = 0
        created.maxPayloadsPerPoint = 1
        scanner = created
        return created
    }

    /** True on the scanner's scan worker threads, the only threads that run `executeScan`. */
    private fun onScanWorker(): Boolean = Thread.currentThread().name.startsWith(SCAN_WORKER_THREAD_PREFIX)

    /** Blocks until [scanner] has recorded [expected] completed scans. Caller supplies the timeout. */
    private fun awaitScansCompleted(
        scanner: ActiveAiScanner,
        expected: Int,
    ) {
        while (scanner.getStatus().scansCompleted < expected) {
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    /** A distinct, in-scope SQLi target whose `id` embeds [id] so it is greppable in a log line. */
    private fun target(id: Int): ActiveScanTarget =
        ActiveScanTarget(
            originalRequest = requestResponse("http://example.com/isolation?id=$id", "id", id.toString()),
            injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", id.toString()),
            vulnHint = VulnHint(VulnClass.SQLI, 50, "test"),
            priority = 50,
        )

    private fun requestResponse(
        url: String,
        name: String,
        value: String,
    ): HttpRequestResponse {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(HttpParameterType.URL)
        whenever(param.name()).thenReturn(name)
        whenever(param.value()).thenReturn(value)

        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        whenever(request.parameters()).thenReturn(listOf(param))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")

        return mock<HttpRequestResponse>().also {
            whenever(it.request()).thenReturn(request)
        }
    }

    private companion object {
        const val LOG_PREFIX = "[ActiveAiScanner] "
        const val SCAN_WORKER_THREAD_PREFIX = "burp-ai-agent-scan-worker-"
        const val EXECUTOR_FIELD = "executor"
        const val PROCESS_QUEUE_METHOD = "processQueue"
        const val TARGET_COUNT = 3
        const val TICKER_TARGET_COUNT = 4
        const val EMPTY_TICKS = 3
        const val FAILING_TARGET_ID = 7
        const val MIN_SUBMIT_ATTEMPTS = 2
        const val POLL_INTERVAL_MS = 20L
        const val SETTLE_TIMEOUT_SECONDS = 15L
        const val TICKER_TIMEOUT_SECONDS = 10L
    }
}

/**
 * An [java.util.concurrent.ExecutorService] that rejects everything, counting attempts.
 *
 * Extends `AbstractExecutorService` rather than mocking the interface on purpose: every `submit`
 * overload funnels through `execute`, so the stub cannot be bypassed by whichever overload Kotlin's
 * resolution picks at the production call site.
 */
private class RejectingExecutorService(
    private val attempts: AtomicInteger,
) : AbstractExecutorService() {
    override fun execute(command: Runnable) {
        attempts.incrementAndGet()
        throw RejectedExecutionException("scan worker pool saturated (test stub)")
    }

    override fun shutdown() = Unit

    override fun shutdownNow(): MutableList<Runnable> = mutableListOf()

    override fun isShutdown(): Boolean = false

    override fun isTerminated(): Boolean = false

    override fun awaitTermination(
        timeout: Long,
        unit: TimeUnit,
    ): Boolean = true
}
