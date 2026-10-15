package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.Collections
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Phase 33 / SC3, LIFE-02 — unloading the passive scanner sends nothing to the AI backend and waits on
 * no AI request.
 *
 * Before this phase `PassiveAiScanner.shutdown()` flushed a partly filled batch synchronously (an AI
 * request on Burp's unload path) and then let queued analyses run. Every case here uses a supervisor
 * that looks like a running backend on the preferred id, so an analysis that is not stopped really
 * reaches `supervisor.send`; the send stub counts every call.
 */
class PassiveUnloadNoTrafficTest {
    private val fixtures = mutableListOf<Fixture>()

    @AfterEach
    fun closeFixtures() {
        fixtures.forEach { it.close() }
    }

    private fun fixture(sendMode: SendMode): Fixture = Fixture(sendMode).also { fixtures += it }

    @Test
    fun unloadWithAPartlyFilledBatchSendsNothingDoesNotWaitAndCountsTheDroppedItems() {
        val f = fixture(SendMode.BLOCK)
        f.scanner.batchQueue.enqueue(f.pending("a.example"))
        f.scanner.batchQueue.enqueue(f.pending("b.example"))

        assertTimeoutPreemptively(Duration.ofSeconds(5)) {
            val startNs = System.nanoTime()
            f.scanner.shutdown()
            val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs)
            assertTrue(elapsedMs < 2_000, "shutdown must not wait on an AI request (took $elapsedMs ms)")
        }

        assertEquals(0, f.sendCalls.get(), "unload must not send the partial batch to the AI backend")
        val dropped = f.outputLines().filter { it.contains("dropped") }
        assertEquals(1, dropped.size, "exactly one dropped-items Output line, got $dropped")
        assertTrue(dropped.single().contains("dropped 2"), "the line counts both batch items: ${dropped.single()}")
    }

    @Test
    fun unloadWithNothingPendingWritesNoDroppedLine() {
        val f = fixture(SendMode.FAIL_FAST)

        f.scanner.shutdown()

        assertEquals(emptyList<String>(), f.outputLines().filter { it.contains("dropped") })
        assertEquals(0, f.sendCalls.get())
    }

    @Test
    fun flushBatchAndSendSingleAnalysisSendNothingAfterUnload() {
        val f = fixture(SendMode.FAIL_FAST)
        f.scanner.shutdown()

        f.scanner.batchQueue.enqueue(f.pending("late-a.example"))
        f.scanner.batchQueue.enqueue(f.pending("late-b.example"))
        f.scanner.flushBatch(f.settings)
        f.scanner.sendSingleAnalysis("late prompt", f.requestResponse("late-c.example"), "LOW", f.settings)

        assertEquals(0, f.sendCalls.get(), "a late flush or single analysis must not reach the AI backend")
    }

    @Test
    fun theExecutorThreadIsTheNamedDaemonPassiveScanWorker() {
        val f = fixture(SendMode.FAIL_FAST)

        val worker =
            f.scanner.executor
                .submit(Callable { Thread.currentThread() })
                .get(WAIT_SECONDS, TimeUnit.SECONDS)

        assertEquals("burp-ai-agent-passive-scan", worker.name)
        assertTrue(worker.isDaemon, "the passive scan worker must be a daemon thread")
    }

    @Test
    fun suggestedTargetsAreClearedAndRefuseLaterAddsAfterUnload() {
        val f = fixture(SendMode.FAIL_FAST)
        f.scanner.suggestedTargets.addAll(listOf(f.target("https://before.example/a?id=1")))

        f.scanner.shutdown()

        assertEquals(0, f.scanner.suggestedTargets.count())
        assertEquals(0, f.scanner.suggestedTargets.addAll(listOf(f.target("https://after.example/b?id=2"))))
        assertEquals(0, f.scanner.suggestedTargets.count())
    }

    @Test
    fun anAnalysisQueuedAtUnloadNeverRunsAndTheRunningTaskIsInterrupted() {
        val f = fixture(SendMode.FAIL_FAST)
        val holderInterrupted = f.holdExecutor(ignoreInterrupts = false)
        assertEquals(1, f.scanner.manualScan(listOf(f.requestResponse("queued.example"))))

        f.scanner.shutdown(ShutdownDeadline(2_000))

        assertEquals(0, f.sendCalls.get(), "a queued analysis must not reach the AI backend")
        assertTrue(holderInterrupted.await(WAIT_SECONDS, TimeUnit.SECONDS), "the running task saw the interrupt")
        assertEquals(emptyList<String>(), f.outputLines().filter { it.contains("Analyzing [") }, "the queued analysis never started")
        val dropped = f.outputLines().filter { it.contains("dropped") }
        assertEquals(1, dropped.size, "exactly one dropped-items Output line, got $dropped")
        assertTrue(dropped.single().contains("dropped 1"), dropped.single())
        assertEquals(emptyList<String>(), f.errorLines(), "an executor that stops in time writes no Error line")
    }

    @Test
    fun aStuckExecutorReturnsWithinTheDeadlineAndWritesOneErrorLine() {
        val f = fixture(SendMode.FAIL_FAST)
        f.holdExecutor(ignoreInterrupts = true)

        assertTimeoutPreemptively(Duration.ofSeconds(5)) {
            f.scanner.shutdown(ShutdownDeadline(300))
        }

        assertEquals(listOf("Unload: Passive scanner did not stop before the unload deadline"), f.errorLines())
    }

    @Test
    fun aFallbackAnalysisInterruptedInsideSendStopsWithoutASecondSendOrAnErrorLine() {
        val f = fixture(SendMode.FAIL_FIRST_THEN_BLOCK)
        f.scanner.batchQueue.enqueue(f.pending("fallback-a.example"))
        f.scanner.batchQueue.enqueue(f.pending("fallback-b.example"))
        // The batch send fails at once, so the fallback sends item a on its own and blocks inside it.
        f.scanner.executor.submit { f.scanner.flushBatch(f.settings) }
        f.awaitSendCalls(2)

        f.scanner.shutdown(ShutdownDeadline(2_000))

        assertTrue(f.sendInterrupted.await(WAIT_SECONDS, TimeUnit.SECONDS), "the running send was interrupted")
        assertEquals(2, f.sendCalls.get(), "no further send after the interrupt (item b is never sent)")
        // The batch's own failure line is written before unload, by design of the fixture; only what the
        // interrupt causes is checked here.
        assertEquals(
            emptyList<String>(),
            f.errorLines().filter { it.contains("Individual fallback failed") || it.contains("did not stop") },
            "an analysis stopped by unload ends quietly, without a per-item failure line or a deadline line",
        )
    }

    @Test
    fun anAnalysisThatReachesTheSendAfterUnloadBeganSendsNothing() {
        PassiveScanCheckRig(singleRequestSettings()).use { rig ->
            val sends = AtomicInteger(0)
            val inBackendCheck = CountDownLatch(1)
            val release = CountDownLatch(1)
            stubRunningBackend(rig, sends, beforeStatus = {
                inBackendCheck.countDown()
                awaitIgnoringInterrupts(release)
            })
            assertEquals(1, rig.scanner.manualScan(listOf(rig.pageGet("late-send.example", smugglingIndicators = false))))
            assertTrue(inBackendCheck.await(WAIT_SECONDS, TimeUnit.SECONDS), "the analysis reached the backend check")

            // The analysis is past every entry gate and stuck in the backend check, which ignores the
            // interrupt, so the unload deadline expires and the analysis goes on after unload began.
            rig.scanner.shutdown(ShutdownDeadline(200))
            release.countDown()
            assertTrue(rig.scanner.executor.awaitTermination(WAIT_SECONDS, TimeUnit.SECONDS), "the worker finished")

            assertEquals(0, sends.get(), "an analysis that reaches the send after unload began must not send")
        }
    }

    @Test
    fun controlTheSameAnalysisSendsOnceWhenNoUnloadHappens() {
        PassiveScanCheckRig(singleRequestSettings()).use { rig ->
            val sends = AtomicInteger(0)
            stubRunningBackend(rig, sends, beforeStatus = {})

            assertEquals(1, rig.scanner.manualScan(listOf(rig.pageGet("control-send.example", smugglingIndicators = false))))
            rig.drain()

            assertEquals(1, sends.get(), "without unload this path reaches supervisor.send, so the case above is not vacuous")
        }
    }

    @Test
    fun aSingleAnalysisWaitingForItsAnswerIsInterruptedQuietlyAtUnload() {
        PassiveScanCheckRig(singleRequestSettings()).use { rig ->
            val sends = AtomicInteger(0)
            val inFlight = CountDownLatch(1)
            // Like a real backend: send returns at once and the answer never comes, so the analysis waits.
            stubRunningBackend(rig, sends, beforeStatus = {}) { inFlight.countDown() }
            assertEquals(1, rig.scanner.manualScan(listOf(rig.pageGet("in-flight.example", smugglingIndicators = false))))
            assertTrue(inFlight.await(WAIT_SECONDS, TimeUnit.SECONDS), "the analysis sent and is waiting")

            assertTimeoutPreemptively(Duration.ofSeconds(5)) {
                rig.scanner.shutdown(ShutdownDeadline(2_000))
            }

            assertEquals(1, sends.get(), "no further send after the interrupt")
            assertEquals(
                emptyList<String>(),
                synchronized(rig.errors) { rig.errors.toList() },
                "an analysis stopped by unload writes no Error line",
            )
        }
    }

    private fun singleRequestSettings(): AgentSettings =
        TestSettings.baselineSettings().copy(
            passiveAiEnabled = true,
            passiveAiScopeOnly = false,
            passiveAiBatchSize = 1,
        )

    /**
     * Makes the rig's supervisor look like a running backend on the preferred id. [beforeStatus] runs on
     * every `status()` call (the first call of the backend check); every send is counted, then [onSend]
     * runs with the send's `onComplete` (by default it fails the send at once).
     */
    private fun stubRunningBackend(
        rig: PassiveScanCheckRig,
        sends: AtomicInteger,
        beforeStatus: () -> Unit,
        onSend: ((Throwable?) -> Unit) -> Unit = { onComplete -> onComplete(IllegalStateException("stub backend error")) },
    ) {
        whenever(rig.supervisor.currentSessionId()).thenReturn("session-under-test")
        whenever(rig.supervisor.status()).thenAnswer {
            beforeStatus()
            AgentSupervisor.Status("running", rig.settings.preferredBackendId)
        }
        whenever(
            rig.supervisor.send(
                any(),
                anyOrNull(),
                anyOrNull(),
                any(),
                any(),
                any(),
                any(),
                anyOrNull(),
                anyOrNull(),
                any(),
                anyOrNull(),
            ),
        ).thenAnswer { invocation ->
            sends.incrementAndGet()
            onSend(invocation.getArgument(ON_COMPLETE_ARG))
            Unit
        }
    }

    /** How the stubbed `supervisor.send` behaves once it has counted the call. */
    internal enum class SendMode {
        /** Blocks (interruptibly) until the fixture closes, like a provider that never answers. */
        BLOCK,

        /** Completes at once with an error, so a batch falls back to one send per item. */
        FAIL_FAST,

        /** The first send fails at once ([FAIL_FAST]); every later send blocks ([BLOCK]). */
        FAIL_FIRST_THEN_BLOCK,
    }

    internal class Fixture(
        private val sendMode: SendMode,
    ) : AutoCloseable {
        val settings: AgentSettings =
            TestSettings.baselineSettings().copy(
                passiveAiEnabled = true,
                passiveAiScopeOnly = false,
                passiveAiBatchSize = 3,
            )
        val sendCalls = AtomicInteger(0)
        val sendInterrupted = CountDownLatch(1)
        private val release = CountDownLatch(1)
        private val output: MutableList<String> = Collections.synchronizedList(mutableListOf())
        private val errors: MutableList<String> = Collections.synchronizedList(mutableListOf())

        private val logging =
            mock<Logging> {
                on { logToOutput(any<String>()) } doAnswer { output += it.getArgument<String>(0) }
                on { logToError(any<String>()) } doAnswer { errors += it.getArgument<String>(0) }
            }
        private val api: MontoyaApi =
            mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also {
                whenever(it.logging()).thenReturn(logging)
            }
        val supervisor: AgentSupervisor =
            mock {
                on { status() } doReturn AgentSupervisor.Status("running", settings.preferredBackendId)
                on { currentSessionId() } doReturn "session-under-test"
                on {
                    send(
                        any(),
                        anyOrNull(),
                        anyOrNull(),
                        any(),
                        any(),
                        any(),
                        any(),
                        anyOrNull(),
                        anyOrNull(),
                        any(),
                        anyOrNull(),
                    )
                } doAnswer { invocation ->
                    val call = sendCalls.incrementAndGet()
                    val onComplete = invocation.getArgument<(Throwable?) -> Unit>(ON_COMPLETE_ARG)
                    val mode =
                        when {
                            sendMode != SendMode.FAIL_FIRST_THEN_BLOCK -> sendMode
                            call == 1 -> SendMode.FAIL_FAST
                            else -> SendMode.BLOCK
                        }
                    when (mode) {
                        SendMode.BLOCK ->
                            try {
                                release.await(WAIT_SECONDS, TimeUnit.SECONDS)
                            } catch (e: InterruptedException) {
                                sendInterrupted.countDown()
                                throw e
                            }
                        else -> onComplete(IllegalStateException("stub backend error"))
                    }
                    Unit
                }
            }
        val scanner = PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { settings }

        fun outputLines(): List<String> = synchronized(output) { output.toList() }

        fun errorLines(): List<String> = synchronized(errors) { errors.toList() }

        /** Waits until `supervisor.send` was called [count] times. */
        fun awaitSendCalls(count: Int) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS)
            while (sendCalls.get() < count) {
                check(System.nanoTime() < deadline) { "only ${sendCalls.get()} of $count sends happened" }
                Thread.sleep(POLL_MS)
            }
        }

        /**
         * Occupies the scanner's single worker until the fixture closes. Returns a latch counted down when
         * the holding task sees an interrupt; with [ignoreInterrupts] it keeps holding the worker anyway.
         */
        fun holdExecutor(ignoreInterrupts: Boolean): CountDownLatch {
            val started = CountDownLatch(1)
            val interrupted = CountDownLatch(1)
            scanner.executor.submit {
                started.countDown()
                var holding = true
                while (holding) {
                    try {
                        release.await(WAIT_SECONDS, TimeUnit.SECONDS)
                        holding = false
                    } catch (_: InterruptedException) {
                        interrupted.countDown()
                        holding = ignoreInterrupts
                    }
                }
            }
            check(started.await(WAIT_SECONDS, TimeUnit.SECONDS)) { "the worker did not start the holding task" }
            return interrupted
        }

        fun requestResponse(host: String): HttpRequestResponse {
            val request = mock<HttpRequest>()
            whenever(request.url()).thenReturn("https://$host/path")
            whenever(request.method()).thenReturn("GET")
            return mock<HttpRequestResponse>().also { whenever(it.request()).thenReturn(request) }
        }

        fun pending(host: String): PendingAnalysis =
            PendingAnalysis(
                metadata = "URL: https://$host/path",
                requestResponse = requestResponse(host),
                minSeverity = "LOW",
                host = host,
            )

        fun target(url: String): ActiveScanTarget {
            val request = mock<HttpRequest>()
            whenever(request.url()).thenReturn(url)
            val rr = mock<HttpRequestResponse>()
            whenever(rr.request()).thenReturn(request)
            return ActiveScanTarget(
                originalRequest = rr,
                injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", "1"),
                vulnHint = VulnHint(VulnClass.SQLI, 90, "evidence"),
            )
        }

        override fun close() {
            release.countDown()
            runCatching { scanner.shutdown() }
        }
    }

    private companion object {
        const val WAIT_SECONDS = 10L

        /** Index of `onComplete` in `AgentSupervisor.send`'s parameter list. */
        const val ON_COMPLETE_ARG = 6

        const val POLL_MS = 10L
    }
}
