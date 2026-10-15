package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.config.Defaults
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * REL-07 / SC6 — the contract of the active scanner's per-request thread pool.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml:47` passes. `ScanRequestExecutorTest` is the
 * approved name; the natural `ScanRequestConcurrencyTest` ends in an excluded suffix and would have
 * removed this suite from the PR gate silently.
 *
 * **Nothing here starts a scanner.** Every assertion is on the factory, on a locally-constructed
 * executor built from the same arguments as the production site, or on source text. No
 * `ActiveAiScanner` is constructed and `setEnabled(true)` is never called, so the suite is fast and
 * cannot leak a live scanner.
 *
 * **Comment stripping in the structural assertions is load-bearing, not cosmetic.** The production
 * file explains this exact pool shape in prose, naming the very tokens counted here — an unstripped
 * reader would score a KDoc mention of a cached pool as a cached pool and invert the gate.
 *
 * **This suite reads source from disk,** so `build.gradle.kts` declares `inputs.dir("src/main/kotlin")`
 * on `tasks.test` under the property name `mainSourceTreeStructuralInputs` (plan 24-01). Without it,
 * reverting the pool shape can leave a cache key close enough that the test task is served from
 * cache and these guards never run, in exactly the commit that breaks them.
 *
 * **No test here compares an elapsed duration to a threshold.** The saturation boundary is proved by
 * latch handshakes whose failure mode is a categorical [assertTimeoutPreemptively] timeout.
 */
class ScanRequestExecutorTest {
    /**
     * REL-07-H — the factory names its threads and marks them daemon.
     *
     * Asserted against the factory directly: no pool is started, so this cannot be flaky and does
     * not depend on the JDK's thread-creation timing.
     */
    @Test
    fun theScanRequestFactoryNamesEveryThreadAndMarksItDaemon() {
        val factory = scanRequestThreadFactory()

        val first = factory.newThread {}
        val second = factory.newThread {}

        assertEquals(
            "${THREAD_NAME_PREFIX}1",
            first.name,
            "REL-07 / SC6 naming: the first thread from a fresh factory must be `${THREAD_NAME_PREFIX}1`. SC6's " +
                "stated purpose is a readable Burp thread dump during a scan against an unresponsive host; an " +
                "anonymous `pool-N-thread-M` bounds the pool and diagnoses nothing.",
        )
        assertEquals(
            "${THREAD_NAME_PREFIX}2",
            second.name,
            "REL-07 / SC6 naming: the counter must advance per thread, so the second is `${THREAD_NAME_PREFIX}2`. A " +
                "repeated name means the counter is shared incorrectly or not incremented, and two stuck " +
                "threads become indistinguishable in a dump.",
        )
        assertTrue(
            first.isDaemon && second.isDaemon,
            "REL-07 / SC6: every scan-request thread must be a daemon. A non-daemon thread orphaned on an " +
                "uninterruptible `sendRequest` keeps the JVM alive after Burp unloads the extension.",
        )
    }

    /**
     * REL-07-G (behavioural half) — the pool's declared shape.
     *
     * Built locally from the same arguments as the production construction site rather than by
     * reflecting a field out of a live scanner: the assertion is about the SHAPE the production site
     * must use, and the structural half below is what pins the production site to it.
     */
    @Test
    fun theScanRequestPoolShapeIsBoundedUnqueuedAndAborting() {
        val pool = newScanRequestPool()
        try {
            assertEquals(
                Defaults.MAX_SCAN_REQUEST_THREADS,
                pool.maximumPoolSize,
                "REL-07 / SC6 ceiling: the per-request pool must top out at " +
                    "`Defaults.MAX_SCAN_REQUEST_THREADS`. Without a ceiling, a scan against a black-holing " +
                    "host spawns one thread per timed-out request forever — `future.cancel(true)` is not " +
                    "documented to interrupt `api.http().sendRequest`, so each orphan survives its timeout.",
            )
            assertInstanceOf(
                SynchronousQueue::class.java,
                pool.queue,
                "REL-07 / SC6 hand-off: the pool must use a SynchronousQueue. It feeds a " +
                    "`future.get(timeout)` that is already time-bounded, so a work queue in front of it only " +
                    "delays a call that cannot wait — and it would also absorb overflow silently instead of " +
                    "letting the abort policy make saturation visible.",
            )
            assertInstanceOf(
                ThreadPoolExecutor.AbortPolicy::class.java,
                pool.rejectedExecutionHandler,
                "REL-07 / SC6 rejection: the handler must be AbortPolicy. CallerRunsPolicy would run the " +
                    "request on the scan worker thread and reintroduce the unbounded blocking the ceiling " +
                    "exists to stop; DiscardPolicy would return a null response with nothing logged.",
            )
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * A-EDGE-4 (boundary) — the pool accepts exactly `MAX_SCAN_REQUEST_THREADS` concurrent tasks and
     * rejects the next one.
     *
     * Both sides are named because both are defects: a pool that accepts more has lost its ceiling,
     * and a pool that rejects earlier drops legitimate scan traffic.
     */
    @Test
    fun theScanRequestPoolAcceptsExactlyItsCeilingAndRejectsOneMore() {
        assertTimeoutPreemptively(Duration.ofSeconds(BOUNDARY_TIMEOUT_SECONDS)) {
            val pool = newScanRequestPool()
            val release = CountDownLatch(1)
            val started = CountDownLatch(Defaults.MAX_SCAN_REQUEST_THREADS)
            try {
                repeat(Defaults.MAX_SCAN_REQUEST_THREADS) { index ->
                    assertDoesNotThrow(
                        {
                            pool.submit {
                                started.countDown()
                                release.await()
                            }
                        },
                        "REL-07 / SC6 boundary: concurrent task ${index + 1} of " +
                            "${Defaults.MAX_SCAN_REQUEST_THREADS} must be ACCEPTED. Rejecting at or below the " +
                            "ceiling means the pool drops legitimate scan traffic — the failure mode opposite " +
                            "to the one the ceiling exists to prevent, and just as invisible to the operator.",
                    )
                }
                started.await()

                assertThrows(
                    RejectedExecutionException::class.java,
                    {
                        pool.submit { release.await() }
                    },
                    "REL-07 / SC6 boundary: with ${Defaults.MAX_SCAN_REQUEST_THREADS} tasks already running and " +
                        "no queue to absorb overflow, concurrent task " +
                        "${Defaults.MAX_SCAN_REQUEST_THREADS + 1} must be rejected. Accepting it means the " +
                        "ceiling is gone and a black-holing host can spawn threads without limit again.",
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
     * while `ActiveAiScanner` quietly went back to an unbounded cached pool.
     */
    @Test
    fun theScannerDeclaresNoUnboundedPoolAndBuildsItsRequestPoolFromTheSharedCeiling() {
        val code = codeLinesOf(SCANNER_SOURCE)

        UNBOUNDED_POOL_FACTORIES.forEach { factory ->
            assertEquals(
                0,
                code.count { it.contains(factory) },
                "REL-07 / SC6: `$factory` creates a pool with no upper bound and must not appear in " +
                    "`$SCANNER_SOURCE`. This is the exact construction SC6 replaces — one orphaned request " +
                    "thread per timed-out request against an unresponsive host, unbounded, with the extension " +
                    "still reporting a healthy scan.",
            )
        }
        assertTrue(
            code.any { it.contains(BOUNDED_POOL_CONSTRUCTION) },
            "REL-07 / SC6, Phase 33 / D-11: `$SCANNER_SOURCE` must build its request pool through the thread " +
                "helper with `$BOUNDED_POOL_CONSTRUCTION`, which takes the ceiling, the queue and the rejection " +
                "policy as explicit arguments, so all three are still stated at the call site rather than " +
                "inherited from an `Executors` convenience factory.",
        )
        assertTrue(
            code.any { it.contains(CEILING_CONSTANT) },
            "REL-07 / SC6: the ceiling must come from `$CEILING_CONSTANT`, not from a literal and not from " +
                "`maxConcurrent`. `requestExecutor` is a `val` initialised at construction while " +
                "`maxConcurrent` is a mutable `var` written later from settings, so deriving it there would " +
                "read the default and never the user's value.",
        )
    }

    /**
     * REL-07-I (structural, source order) — the submit sits inside the guarded region.
     *
     * A source-order assertion rather than a behavioural one because saturating the real pool from a
     * test would mean racing 33 live request threads against a mock, which is the flake this phase's
     * validation contract rules out.
     */
    @Test
    fun theRequestSubmitSitsInsideTheTryThatHandlesRejection() {
        val body = functionBody(SEND_REQUEST_SIGNATURE)

        val tryIndex = body.indexOfFirst { it.contains(TRY_OPENER) }
        val submitIndex = body.indexOfFirst { it.contains(REQUEST_SUBMIT) }

        assertTrue(
            tryIndex >= 0 && submitIndex >= 0,
            "Expected `sendRequestWithTimeout` to contain both `$TRY_OPENER` and `$REQUEST_SUBMIT`. Missing " +
                "either means the function was restructured and this guard must be re-aimed deliberately. " +
                "Body read:\n${body.joinToString("\n")}",
        )
        assertTrue(
            submitIndex > tryIndex,
            "REL-07 / SC6 (REL-07-I): `$REQUEST_SUBMIT` must appear AFTER `$TRY_OPENER`. Submitted above the " +
                "try, a saturated pool's rejection escapes `sendRequestWithTimeout` entirely, climbs through " +
                "`executeScan` into the per-target catch, and aborts a whole target with a message of " +
                "`null` — `RejectedExecutionException` usually carries none. Inside the try it degrades to a " +
                "logged `null`, exactly as a timeout already does. Found the try at line ${tryIndex + 1} and " +
                "the submit at line ${submitIndex + 1} of the comment-stripped body.",
        )
        assertTrue(
            body.any { it.contains(REJECTION_TYPE) },
            "REL-07 / SC6 (REL-07-I): `sendRequestWithTimeout` must carry a `$REJECTION_TYPE` arm. Moving the " +
                "submit inside the try without one only changes WHICH generic arm swallows it, and the " +
                "operator still gets `Request error: null` instead of a line naming pool saturation.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** A pool built from exactly the arguments `ActiveAiScanner` uses for `requestExecutor`. */
    private fun newScanRequestPool(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            0,
            Defaults.MAX_SCAN_REQUEST_THREADS,
            Defaults.SCAN_REQUEST_THREAD_KEEPALIVE_SECONDS,
            TimeUnit.SECONDS,
            SynchronousQueue(),
            scanRequestThreadFactory(),
            ThreadPoolExecutor.AbortPolicy(),
        )

    /**
     * The comment-stripped lines of the function whose declaration contains [signature], up to the
     * next declaration at any visibility.
     */
    private fun functionBody(signature: String): List<String> {
        val code = codeLinesOf(SCANNER_SOURCE)
        val start = code.indexOfFirst { it.contains(signature) }
        assertTrue(
            start >= 0,
            "Expected to find a declaration containing `$signature` in `$SCANNER_SOURCE`. If it was renamed, " +
                "re-aim this guard deliberately rather than deleting it.",
        )
        val relativeEnd =
            code.drop(start + 1).indexOfFirst { line ->
                val trimmed = line.trimStart()
                DECLARATION_STARTS.any { trimmed.startsWith(it) }
            }
        val end = if (relativeEnd < 0) code.size else start + 1 + relativeEnd
        return code.subList(start, end)
    }

    /**
     * The non-comment lines of [path], read from disk.
     *
     * A line counts as a comment when its first non-space characters are a line-comment marker, a
     * continuation asterisk, or a block-comment opener — the same rule
     * `SettingsPersistQueueTest.codeLinesOf` and `SchedulerGuardCoverageTest.codeLinesOf` apply. (The
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
        const val SCANNER_SOURCE = "com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt"
        const val THREAD_NAME_PREFIX = "burp-ai-agent-scan-request-"
        const val BOUNDED_POOL_CONSTRUCTION = "ExtensionThreads.boundedPool("
        const val CEILING_CONSTANT = "Defaults.MAX_SCAN_REQUEST_THREADS"
        const val SEND_REQUEST_SIGNATURE = "fun sendRequestWithTimeout("
        const val TRY_OPENER = "return try {"
        const val REQUEST_SUBMIT = "requestExecutor.submit("
        const val REJECTION_TYPE = "RejectedExecutionException"
        const val BOUNDARY_TIMEOUT_SECONDS = 15L

        /**
         * The `Executors` factories that hand back a pool with no upper bound on thread count. A
         * bare `Executors.new` prefix would also match the bounded `newFixedThreadPool` and
         * `newSingleThreadScheduledExecutor` this class legitimately uses.
         */
        val UNBOUNDED_POOL_FACTORIES =
            listOf(
                "Executors.newCachedThreadPool(",
                "Executors.newWorkStealingPool(",
                "Executors.newVirtualThreadPerTaskExecutor(",
            )

        val DECLARATION_STARTS = listOf("private fun ", "internal fun ", "fun ", "private val ", "internal val ")
    }
}
