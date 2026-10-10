package com.six2dez.burp.aiagent

import com.six2dez.burp.aiagent.config.Defaults
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.ThreadPoolExecutor

/**
 * REL-07 / SC6 — the contract of the extension-wide worker pool (`App.workerPool`).
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml:47` passes. `WorkerPoolExecutorTest` is the
 * approved name. Both natural alternatives for this subject are traps: `WorkerPoolSupervisionTest`
 * (this pool is owned by `AgentSupervisor`'s restart path) and `WorkerPoolRestartPolicyTest` (its
 * contract is about what happens on saturation) each end in an excluded suffix, and either would
 * have removed this suite from the PR gate silently while still passing locally.
 *
 * **Nothing here constructs an `App` and nothing spawns a real service process.** Every assertion is
 * on the factory, on a locally-constructed pool built from the same arguments as the production site,
 * or on source text. The suite needs no live Burp and no `ollama serve` on the machine running it.
 *
 * **Comment stripping in the structural assertions is load-bearing, not cosmetic.** `App.kt`
 * deliberately explains this pool's shape in prose and names the two rejected alternatives —
 * including a cached pool and a caller-runs policy — right above the construction. An unstripped
 * reader would score that explanation as the very construction it forbids and invert the gate.
 *
 * **This suite reads source from disk,** so `build.gradle.kts` declares `inputs.dir("src/main/kotlin")`
 * on `tasks.test` under the property name `mainSourceTreeStructuralInputs` (plan 24-01). Without it,
 * reverting the pool shape can leave a cache key close enough that the test task is served from cache
 * and these guards never run, in exactly the commit that breaks them — the measured 22-09 defect.
 *
 * **No test here compares an elapsed duration to a threshold.** Concurrency is proved by latch
 * handshakes whose failure mode is a categorical [assertTimeoutPreemptively] timeout.
 */
class WorkerPoolExecutorTest {
    /**
     * REL-07-H — the factory names its threads and marks them daemon.
     *
     * Asserted against the factory directly: no pool is started, so this cannot be flaky and does not
     * depend on the JDK's thread-creation timing. It is also the only shape that can assert anything
     * about an IDLE pool — a fixed pool creates its threads lazily, so a pool with no submitted work
     * holds no threads to inspect.
     */
    @Test
    fun theWorkerPoolFactoryNamesEveryThreadAndMarksItDaemon() {
        val factory = workerPoolThreadFactory()

        val first = factory.newThread {}
        val second = factory.newThread {}

        assertEquals(
            "${THREAD_NAME_PREFIX}1",
            first.name,
            "REL-07 / SC6 naming: the first thread from a fresh factory must be `${THREAD_NAME_PREFIX}1`. " +
                "SC6's stated purpose is a readable Burp thread dump; an anonymous `pool-N-thread-M` bounds " +
                "the pool and diagnoses nothing, which is half of what this requirement asks for.",
        )
        assertEquals(
            "${THREAD_NAME_PREFIX}2",
            second.name,
            "REL-07 / SC6 naming: the counter must advance per thread, so the second is " +
                "`${THREAD_NAME_PREFIX}2`. A repeated name means the counter is shared incorrectly or never " +
                "incremented, and two busy worker threads become indistinguishable in a dump.",
        )
        assertTrue(
            first.isDaemon && second.isDaemon,
            "REL-07 / SC6: every worker thread must be a daemon. A non-daemon worker still running an " +
                "auto-restart task keeps the JVM alive after Burp unloads the extension — the same defect " +
                "Phase 23 D-05 records for the service log pump.",
        )
    }

    /**
     * REL-07-G (behavioural half) — the pool's declared ceiling.
     *
     * Built locally from the same arguments as the production construction site rather than by
     * reflecting a field out of the `App` singleton: the assertion is about the SHAPE the production
     * site must use, and the structural half below is what pins the production site to it. `App` is
     * an object that needs a live `MontoyaApi`, so reflecting into it would need a live Burp.
     */
    @Test
    fun theWorkerPoolShapeIsBoundedAtTheSharedCeiling() {
        val pool = newWorkerPool()
        try {
            assertEquals(
                Defaults.MAX_WORKER_THREADS,
                pool.maximumPoolSize,
                "REL-07 / SC6 ceiling: the extension-wide worker pool must top out at " +
                    "`Defaults.MAX_WORKER_THREADS`. Without a ceiling this pool is a cached pool again, and " +
                    "a backend that crashes in a tight loop spawns one worker thread per restart attempt " +
                    "with nothing in the error log to say so (T-24-17).",
            )
            assertEquals(
                Defaults.MAX_WORKER_THREADS,
                pool.corePoolSize,
                "REL-07 / SC6 ceiling: a fixed pool's core size equals its maximum. A core size below the " +
                    "maximum means the pool was hand-rolled with a queue in front of it, and with an " +
                    "unbounded queue the extra threads above the core would never be created at all — the " +
                    "ceiling would read correct and be unreachable.",
            )
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * A-EDGE-4 (boundary) — saturation QUEUES here. It does not reject.
     *
     * Both sides are named because the absence of a rejection is the deliberate design, not an
     * oversight: this is the documented difference from `requestExecutor` in plan 24-02, where a
     * `SynchronousQueue` plus `AbortPolicy` is correct because saturation must be observable and its
     * throw site is handled. Here it must not throw at all.
     */
    @Test
    fun theWorkerPoolAcceptsItsCeilingConcurrentlyAndQueuesTheNextTaskInsteadOfRejectingIt() {
        assertTimeoutPreemptively(Duration.ofSeconds(BOUNDARY_TIMEOUT_SECONDS)) {
            val pool = newWorkerPool()
            val release = CountDownLatch(1)
            val started = CountDownLatch(Defaults.MAX_WORKER_THREADS)
            val queuedTaskRan = CountDownLatch(1)
            try {
                repeat(Defaults.MAX_WORKER_THREADS) {
                    pool.submit {
                        started.countDown()
                        release.await()
                    }
                }
                // Completes only if MAX_WORKER_THREADS tasks are running AT ONCE: each counts down and
                // then blocks, so a pool with fewer live threads never reaches zero and the enclosing
                // preemptive timeout reports it categorically rather than as a flaky count.
                started.await()

                assertDoesNotThrow(
                    {
                        pool.submit {
                            queuedTaskRan.countDown()
                        }
                    },
                    "REL-07 / SC6 boundary: with the ceiling already saturated, task " +
                        "${Defaults.MAX_WORKER_THREADS + 1} must still be ACCEPTED. This pool's contract is " +
                        "that saturation degrades to QUEUEING, never to loss and never to a throw: the submit " +
                        "in `AgentSupervisor.scheduleRestart` is not inside a try, so a " +
                        "RejectedExecutionException here would propagate uncaught and kill the auto-restart " +
                        "path outright (T-24-18). That is the deliberate, documented difference from the " +
                        "scanner's `requestExecutor`, whose AbortPolicy IS correct because its throw site is " +
                        "handled — do not 'fix' the inconsistency in either direction.",
                )
                assertEquals(
                    1,
                    pool.queue.size,
                    "REL-07 / SC6 boundary: the overflow task must be sitting in the pool's work queue. A " +
                        "queue size of 0 with every worker busy means the task was silently discarded " +
                        "(DiscardPolicy / DiscardOldestPolicy) or run inline on this thread " +
                        "(a caller-runs policy) — the second of which is how a never-returning task would " +
                        "reach the EDT that Phase 23 (REL-05) spent eight plans clearing.",
                )

                release.countDown()
                queuedTaskRan.await()
                assertEquals(
                    0L,
                    queuedTaskRan.count,
                    "REL-07 / SC6 boundary: the queued task must actually run once a worker frees up. A " +
                        "queue that accepts work and never drains it is task loss with extra steps, and it " +
                        "is exactly what T-24-09 describes — a bounded pool whose every thread is parked in " +
                        "a never-returning task while restart work piles up behind it, unreported.",
                )
            } finally {
                release.countDown()
                pool.shutdownNow()
            }
        }
    }

    /**
     * REL-07-G (structural half) — the production site really uses this shape.
     *
     * Without this, the behavioural assertions above would keep passing against a locally-built pool
     * while `App.kt` quietly went back to an unbounded cached pool.
     */
    @Test
    fun appDeclaresNoUnboundedPoolAndBuildsItsWorkerPoolFromTheSharedCeiling() {
        val code = codeLinesOf(APP_SOURCE)

        UNBOUNDED_POOL_FACTORIES.forEach { factory ->
            assertEquals(
                0,
                code.count { it.contains(factory) },
                "REL-07 / SC6: `$factory` creates a pool with no upper bound on thread count and must not " +
                    "appear in `$APP_SOURCE`. This is the exact construction SC6 replaces — the pool is " +
                    "shared by every `AgentSupervisor` restart submit, so an unbounded one is a way for a " +
                    "flapping backend to spawn threads without limit (T-24-17).",
            )
        }
        val construction =
            code.firstOrNull { it.contains(BOUNDED_POOL_CONSTRUCTION) }
        assertTrue(
            construction != null,
            "REL-07 / SC6: `$APP_SOURCE` must build its worker pool with `$BOUNDED_POOL_CONSTRUCTION`. A " +
                "fixed pool is the deliberate choice here rather than the explicit ThreadPoolExecutor used " +
                "for the scanner's pool: it bounds THREADS while keeping an unbounded queue, so saturation " +
                "queues instead of reaching a rejection handler that this pool's callers cannot survive.",
        )
        // Both remaining checks are scoped to the construction LINE, not to the file. Scoped to the
        // file, the ceiling check would also be satisfied by an unrelated mention and the factory check
        // by the factory's own declaration further down — either would keep passing against a pool that
        // no longer uses them.
        val constructionLine = construction.orEmpty()
        assertTrue(
            constructionLine.contains(CEILING_CONSTANT),
            "REL-07 / SC6: the ceiling at the construction site must come from `$CEILING_CONSTANT` and not " +
                "from a literal. detekt's MagicNumber rule is active with a baseline QUAL-07 forbids " +
                "growing, and a shared constant is also what lets this suite assert the same number the " +
                "production site uses instead of restating it. Construction line read: `$constructionLine`",
        )
        assertTrue(
            constructionLine.contains(NAMED_FACTORY_CALL),
            "REL-07 / SC6: the pool must be built WITH `$NAMED_FACTORY_CALL`. `newFixedThreadPool` has a " +
                "one-argument overload that bounds the pool and leaves every thread named " +
                "`pool-N-thread-M`; that satisfies the ceiling and none of SC6's readable-thread-dump goal. " +
                "Construction line read: `$constructionLine`",
        )

        val backendRegistryStep = code.indexOfFirst { it.contains(BACKEND_REGISTRY_STEP) }
        val cliTempFilesStep = code.indexOfFirst { it.contains(CLI_TEMP_FILES_STEP) }
        val workerPoolStep = code.indexOfFirst { it.contains(WORKER_POOL_STEP) }

        assertTrue(
            backendRegistryStep >= 0 && cliTempFilesStep >= 0 && workerPoolStep >= 0,
            "Expected `$APP_SOURCE` to contain all three shutdown steps `$BACKEND_REGISTRY_STEP`, " +
                "`$CLI_TEMP_FILES_STEP` and `$WORKER_POOL_STEP`. A missing one means `shutdown()` was " +
                "restructured and this guard must be re-aimed deliberately rather than deleted. Found them " +
                "at ${backendRegistryStep + 1}, ${cliTempFilesStep + 1} and ${workerPoolStep + 1} of the " +
                "comment-stripped source.",
        )
        assertTrue(
            backendRegistryStep < cliTempFilesStep && cliTempFilesStep < workerPoolStep,
            "REL-07 / SC5 / D-03 ordering: the shutdown steps must stay in the order backend registry -> " +
                "CLI temp files -> worker pool. The CLI executor lives under the backend registry, so the " +
                "temp-file drain only sweeps a settled set once the registry is down (plan 24-04); moving it " +
                "after the worker-pool step would drain while in-flight CLI calls can still register files. " +
                "Bounding the worker pool in this plan did not move the step, and nothing here should.",
        )
    }

    /**
     * SC6 prerequisite (structural) — the never-returning stdout pump is NOT on the bounded pool.
     *
     * This is the assertion the whole ordering of plan 24-05 exists to protect. It is separate from
     * the ceiling assertions because a correct ceiling with the pump back on the pool is strictly
     * worse than no ceiling at all.
     */
    @Test
    fun theSupervisorKeepsOnlyTheAutoRestartSubmitOnTheBoundedWorkerPool() {
        val code = codeLinesOf(SUPERVISOR_SOURCE)

        assertEquals(
            1,
            code.count { it.contains(WORKER_POOL_SUBMIT) },
            "REL-07 / SC6 (T-24-09): `$WORKER_POOL_SUBMIT` must appear EXACTLY ONCE in " +
                "`$SUPERVISOR_SOURCE` — the short, bursty auto-restart submit in `scheduleRestart`, which " +
                "is the workload a bounded pool is for. Two occurrences almost certainly means the service " +
                "stdout pump is back on the pool. That pump calls `reader.forEachLine`, so it occupies its " +
                "worker thread for the ENTIRE lifetime of the service process: with two managed services " +
                "(ollama-serve, lmstudio-server) it parks two of the pool's " +
                "${Defaults.MAX_WORKER_THREADS} threads permanently, and every auto-restart task then " +
                "queues behind them forever on an unbounded queue with nothing reporting the stall. That " +
                "is the exact defect this plan's task ordering exists to prevent — bounding a pool that " +
                "still hosts an unbounded-duration task stalls the extension.",
        )
        assertEquals(
            1,
            code.count { it.contains(SERVICE_THREAD_NAME_PREFIX) },
            "REL-07 / SC6: `$SUPERVISOR_SOURCE` must name its service stdout pump thread exactly once, as " +
                "`$SERVICE_THREAD_NAME_PREFIX<name>`. Zero occurrences means the pump went back onto a " +
                "pool or onto an anonymous thread; more than one means a second pump was introduced " +
                "without going through this guard.",
        )
        assertTrue(
            code.any { it.contains(SERVICE_PUMP_DAEMON_FLAG) },
            "REL-07 / SC6 (T-24-19): the service pump thread must set `$SERVICE_PUMP_DAEMON_FLAG` " +
                "explicitly. Phase 23 D-05 requires the flag be set rather than assumed — \"a daemon thread " +
                "never blocks unload\" is only true if the flag is actually set, and a non-daemon pump " +
                "holds the JVM open after Burp quits.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** A pool built from exactly the arguments `App` uses for `workerPool`. */
    private fun newWorkerPool(): ThreadPoolExecutor =
        Executors.newFixedThreadPool(Defaults.MAX_WORKER_THREADS, workerPoolThreadFactory())
            as ThreadPoolExecutor

    /**
     * The non-comment lines of [path], read from disk.
     *
     * A line counts as a comment when its first non-space characters are a line-comment marker, a
     * continuation asterisk, or a block-comment opener — the same rule
     * `SettingsPersistQueueTest.codeLinesOf` and `ScanRequestExecutorTest.codeLinesOf` apply. (The
     * three markers are written out longhand rather than quoted, because Kotlin block comments nest:
     * a literal opener inside this KDoc would open a nested comment and swallow the rest of the file.)
     */
    private fun codeLinesOf(path: String): List<String> {
        // SourceRoots.file fails naming both production roots when the file is in neither or in both.
        val file = SourceRoots.file(path)
        return file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }
    }

    private companion object {
        const val APP_SOURCE = "com/six2dez/burp/aiagent/App.kt"
        const val SUPERVISOR_SOURCE = "com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt"
        const val THREAD_NAME_PREFIX = "burp-ai-agent-worker-"
        const val SERVICE_THREAD_NAME_PREFIX = "burp-ai-agent-service-"
        const val SERVICE_PUMP_DAEMON_FLAG = "pumpThread.isDaemon = true"
        const val BOUNDED_POOL_CONSTRUCTION = "Executors.newFixedThreadPool("
        const val CEILING_CONSTANT = "Defaults.MAX_WORKER_THREADS"
        const val NAMED_FACTORY_CALL = "workerPoolThreadFactory()"
        const val WORKER_POOL_SUBMIT = "workerPool.submit"
        const val BACKEND_REGISTRY_STEP = "safeShutdownStep(\"Backend registry\")"
        const val CLI_TEMP_FILES_STEP = "safeShutdownStep(\"CLI temp files\")"
        const val WORKER_POOL_STEP = "safeShutdownStep(\"Worker pool\")"
        const val BOUNDARY_TIMEOUT_SECONDS = 15L

        /**
         * The `Executors` factories that hand back a pool with no upper bound on thread count. A bare
         * `Executors.new` prefix would also match the bounded `newFixedThreadPool` this file
         * legitimately uses.
         */
        val UNBOUNDED_POOL_FACTORIES =
            listOf(
                "Executors.newCachedThreadPool(",
                "Executors.newWorkStealingPool(",
                "Executors.newVirtualThreadPerTaskExecutor(",
            )
    }
}
