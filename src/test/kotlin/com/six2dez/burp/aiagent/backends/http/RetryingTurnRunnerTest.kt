package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.util.ExtensionThreads
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 34 / LOOP-01 / D-06 — the [RetryingTurnRunner] contract, driven only through its
 * `scheduleAfter` seam, so no case waits out a real backoff.
 *
 * The seam records each scheduled retry (its delay, its task and a handle the runner may cancel) and
 * never runs it inline, because the runner holds its lock while scheduling. A case runs a recorded
 * task explicitly, on the runner's real worker, once `scheduleAfter` has returned.
 *
 * Pins: the retry schedule and the attempt that ends it, the real breaker opening before a sixth
 * attempt, a non-retryable failure ending at once, FIFO across a backoff, stop during a backoff,
 * refused submits, a throwing onComplete, and a throwing prologue (RESEARCH Pitfalls 1, 2 and 10).
 */
class RetryingTurnRunnerTest {
    private val executor: ScheduledExecutorService = ExtensionThreads.scheduled("retry-runner-test")
    private val alive = AtomicBoolean(true)
    private val errors = CopyOnWriteArrayList<String>()
    private val scheduled = LinkedBlockingQueue<Scheduled>()
    private val savedRetryHook = BackendDiagnostics.retry

    /** One retry the runner asked the seam to schedule. */
    private data class Scheduled(
        val delayMs: Long,
        val task: Runnable,
        val handle: CompletableFuture<Unit>,
    )

    @AfterEach
    fun tearDown() {
        BackendDiagnostics.retry = savedRetryHook
        executor.shutdownNow()
    }

    @Test
    fun retriesFollowTheDelayTableThenTheSixthAttemptsOwnErrorEndsTheTurn() {
        val events = CopyOnWriteArrayList<BackendDiagnostics.RetryEvent>()
        val attempts = AtomicInteger(0)
        val runner = newRunner(CircuitBreaker(failureThreshold = Int.MAX_VALUE))
        withRetryEvents(events) {
            val outcome = Outcome()
            runner.submit(
                prologue = {},
                attempt = { error("connection refused #${attempts.incrementAndGet()}") },
                onComplete = outcome::record,
            )

            val delays = (1..5).map { nextScheduled().also(::runScheduled).delayMs }

            val error = outcome.await()
            assertEquals(listOf(500L, 1000L, 1500L, 2000L, 3000L), delays, "the scheduled delays")
            assertEquals(listOf(1, 2, 3, 4, 5), events.map { it.attempt }, "one retry event per scheduled retry")
            assertTrue(events.all { it.backendId == LABEL }, "every retry event carries the label")
            assertEquals(listOf(500L, 1000L, 1500L, 2000L, 3000L), events.map { it.delayMs }, "the logged delays")
            assertEquals("connection refused #6", error?.message, "the sixth attempt's own error ends the turn")
            assertEquals(6, attempts.get(), "six attempts in all")
            assertTrue(scheduled.isEmpty(), "no retry is scheduled after the last attempt")
            assertEquals(1, outcome.calls.get(), "onComplete runs once")
        }
    }

    @Test
    fun theRealBreakerOpensBeforeASixthAttempt() {
        val attempts = AtomicInteger(0)
        val runner = newRunner(HttpBackendSupport.newCircuitBreaker())
        withRetryEvents(CopyOnWriteArrayList()) {
            val outcome = Outcome()
            runner.submit(
                prologue = {},
                attempt = {
                    attempts.incrementAndGet()
                    error("connection refused")
                },
                onComplete = outcome::record,
            )

            repeat(5) { runScheduled(nextScheduled()) }

            val error = outcome.await()
            assertNotNull(error)
            assertTrue(error!!.message.orEmpty().contains("circuit open"), "the breaker ends the turn: ${error.message}")
            assertTrue(error.message.orEmpty().startsWith(CIRCUIT_NAME), "the error names the circuit: ${error.message}")
            assertEquals(5, attempts.get(), "no sixth attempt runs")
            assertTrue(scheduled.isEmpty(), "nothing more is scheduled")
        }
    }

    @Test
    fun aNonRetryableFailureCompletesAtOnce() {
        val events = CopyOnWriteArrayList<BackendDiagnostics.RetryEvent>()
        // Threshold 1: a single recordFailure would open the breaker, so CLOSED proves it never ran.
        val breaker = CircuitBreaker(failureThreshold = 1)
        val runner = newRunner(breaker)
        withRetryEvents(events) {
            val outcome = Outcome()
            runner.submit(
                prologue = {},
                attempt = { throw IllegalArgumentException("bad request") },
                onComplete = outcome::record,
            )

            assertEquals("bad request", outcome.await()?.message)
            assertTrue(events.isEmpty(), "no retry event")
            assertTrue(scheduled.isEmpty(), "nothing is scheduled")
            assertEquals(CircuitBreaker.State.CLOSED, breaker.state(), "recordFailure is not called")
            assertTrue(errors.contains("exception: bad request"), "the failure is logged: $errors")
        }
    }

    @Test
    fun aTurnSubmittedDuringABackoffStartsOnlyAfterThatTurnCompletes() {
        val trace = CopyOnWriteArrayList<String>()
        val runner = newRunner(CircuitBreaker(failureThreshold = Int.MAX_VALUE))
        withRetryEvents(CopyOnWriteArrayList()) {
            val aAttempts = AtomicInteger(0)
            val turnA = Outcome { trace += "A-complete" }
            runner.submit(
                prologue = { trace += "A-prologue" },
                attempt = { complete ->
                    trace += "A-attempt"
                    if (aAttempts.incrementAndGet() == 1) error("connection refused")
                    complete(null)
                },
                onComplete = turnA::record,
            )
            val retryOfA = nextScheduled()

            val turnB = Outcome { trace += "B-complete" }
            runner.submit(
                prologue = { trace += "B-prologue" },
                attempt = { complete ->
                    trace += "B-attempt"
                    complete(null)
                },
                onComplete = turnB::record,
            )
            flushWorker()
            assertFalse(trace.contains("B-prologue"), "turn B must not start during turn A's backoff: $trace")

            runScheduled(retryOfA)

            assertNull(turnA.await(), "turn A succeeds on its retry")
            assertNull(turnB.await(), "turn B succeeds")
            assertEquals(
                listOf("A-prologue", "A-attempt", "A-attempt", "A-complete", "B-prologue", "B-attempt", "B-complete"),
                trace.toList(),
                "turn B starts only after turn A's completion ran",
            )
        }
    }

    @Test
    fun aStopDuringABackoffCompletesTheTurnOnceAndCancelsTheRetry() {
        val runner = newRunner(CircuitBreaker(failureThreshold = Int.MAX_VALUE))
        withRetryEvents(CopyOnWriteArrayList()) {
            val aAttempts = AtomicInteger(0)
            val turnA = Outcome()
            runner.submit(
                prologue = {},
                attempt = {
                    aAttempts.incrementAndGet()
                    error("connection refused A")
                },
                onComplete = turnA::record,
            )
            val retryOfA = nextScheduled()
            val bPrologueRan = AtomicBoolean(false)
            val turnB = Outcome()
            runner.submit(prologue = { bPrologueRan.set(true) }, attempt = { it(null) }, onComplete = turnB::record)

            runner.stop()

            assertEquals("connection refused A", turnA.await()?.message, "turn A completes with its last error")
            assertTrue(retryOfA.handle.isCancelled, "the pending retry is cancelled")
            assertTrue(errors.contains("exception: connection refused A"), "the stopped turn is logged: $errors")
            assertEquals("Connection closed", turnB.await()?.message, "the queued turn completes with Connection closed")

            // A retry task that slipped past the cancel still sends nothing.
            runScheduled(retryOfA)
            flushWorker()

            assertEquals(1, aAttempts.get(), "no attempt runs after the stop")
            assertEquals(1, turnA.calls.get(), "turn A completes exactly once")
            assertEquals(1, turnB.calls.get(), "turn B completes exactly once")
            assertFalse(bPrologueRan.get(), "the queued turn never starts")
        }
    }

    @Test
    fun aRefusedSubmitCompletesWithConnectionClosedWithoutThrowing() {
        val stoppedRunner = newRunner(CircuitBreaker())
        stoppedRunner.stop()
        val afterStop = Outcome()
        val prologueRan = AtomicBoolean(false)
        assertDoesNotThrow { stoppedRunner.submit({ prologueRan.set(true) }, { it(null) }, afterStop::record) }
        assertEquals("Connection closed", afterStop.await()?.message, "a submit after stop()")
        assertFalse(prologueRan.get(), "the refused turn never starts")

        val rejecting = ExtensionThreads.scheduled("retry-runner-rejecting").also { it.shutdown() }
        val rejectingRunner =
            RetryingTurnRunner(rejecting, LABEL, CIRCUIT_NAME, CircuitBreaker(), alive::get, {}, { errors += it }, ::record)
        val rejected = Outcome()
        assertDoesNotThrow { rejectingRunner.submit({}, { it(null) }, rejected::record) }
        assertEquals("Connection closed", rejected.await()?.message, "a submit the executor rejects")
        assertEquals(1, rejected.calls.get())
    }

    @Test
    fun aThrowingOnCompleteStillLetsTheNextTurnRun() {
        val runner = newRunner(CircuitBreaker())
        val aStarted = CountDownLatch(1)
        val releaseA = CountDownLatch(1)
        val aCalls = AtomicInteger(0)
        runner.submit(
            prologue = {},
            attempt = { complete ->
                aStarted.countDown()
                assertTrue(releaseA.await(AWAIT_SECONDS, TimeUnit.SECONDS), "turn A was never released")
                complete(null)
            },
            onComplete = {
                aCalls.incrementAndGet()
                error("boom")
            },
        )
        assertTrue(aStarted.await(AWAIT_SECONDS, TimeUnit.SECONDS), "turn A never started")
        val turnB = Outcome()
        runner.submit(prologue = {}, attempt = { it(null) }, onComplete = turnB::record)

        releaseA.countDown()

        assertNull(turnB.await(), "turn B runs after turn A's callback threw")
        assertEquals(1, aCalls.get(), "turn A's onComplete ran exactly once")
        assertTrue(errors.contains("onComplete failed: boom"), "the throwing callback is logged: $errors")
    }

    @Test
    fun aThrowingPrologueCompletesItsTurnWithThePrologueError() {
        val runner = newRunner(CircuitBreaker())
        val attemptRan = AtomicBoolean(false)
        val outcome = Outcome()
        runner.submit(
            prologue = { error("prologue broke") },
            attempt = {
                attemptRan.set(true)
                it(null)
            },
            onComplete = outcome::record,
        )

        assertEquals("prologue broke", outcome.await()?.message)
        assertFalse(attemptRan.get(), "no attempt runs")
        assertTrue(errors.contains("exception: prologue broke"), "the prologue failure is logged: $errors")
        assertEquals(1, outcome.calls.get())
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun newRunner(breaker: CircuitBreaker): RetryingTurnRunner {
        val errorLog: (String) -> Unit = { errors += it }
        return RetryingTurnRunner(executor, LABEL, CIRCUIT_NAME, breaker, alive::get, {}, errorLog, ::record)
    }

    /** The `scheduleAfter` seam: records the retry, never runs it. */
    private fun record(
        delayMs: Long,
        task: Runnable,
    ): Future<*> {
        val handle = CompletableFuture<Unit>()
        scheduled += Scheduled(delayMs, task, handle)
        return handle
    }

    private fun nextScheduled(): Scheduled {
        val next = scheduled.poll(AWAIT_SECONDS, TimeUnit.SECONDS)
        assertNotNull(next, "no retry was scheduled")
        return next!!
    }

    /** Runs a recorded retry on the runner's worker, as the scheduler would, and waits for it. */
    private fun runScheduled(retry: Scheduled) {
        executor.submit(retry.task).get(AWAIT_SECONDS, TimeUnit.SECONDS)
    }

    /** Waits until every task already handed to the worker has run. */
    private fun flushWorker() {
        executor.submit {}.get(AWAIT_SECONDS, TimeUnit.SECONDS)
    }

    private fun withRetryEvents(
        events: MutableList<BackendDiagnostics.RetryEvent>,
        body: () -> Unit,
    ) {
        BackendDiagnostics.retry = { if (it.backendId == LABEL) events += it }
        try {
            body()
        } finally {
            BackendDiagnostics.retry = savedRetryHook
        }
    }

    /** One turn's outcome: every onComplete call is counted, the first error is kept. */
    private class Outcome(
        private val onFirst: () -> Unit = {},
    ) {
        val calls = AtomicInteger(0)
        private val error = AtomicReference<Throwable?>(null)
        private val done = CountDownLatch(1)

        fun record(err: Throwable?) {
            if (calls.incrementAndGet() == 1) {
                error.set(err)
                onFirst()
                done.countDown()
            }
        }

        fun await(): Throwable? {
            assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the turn did not complete in ${AWAIT_SECONDS}s")
            return error.get()
        }
    }

    private companion object {
        const val LABEL = "retry-runner-test-label"
        const val CIRCUIT_NAME = "Runner Test"
        const val AWAIT_SECONDS = 10L
    }
}
