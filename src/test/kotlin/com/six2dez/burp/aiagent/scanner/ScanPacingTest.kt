package com.six2dez.burp.aiagent.scanner

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 34 / D-04 — the three exits of the active scanner's pacing wait: a release (OFF, unload), an
 * interrupt, and the delay running out. Every wait is bounded, so a broken exit fails fast instead of
 * hanging the suite.
 */
class ScanPacingTest {
    @Test
    fun aReleaseEndsAPauseAtOnceWithoutAnInterrupt() {
        val pacing = ScanPacing()
        val outcome = PausingThread(pacing, LONG_PAUSE_MS).start()

        outcome.awaitEntered()
        pacing.release()

        assertTrue(outcome.finished.await(EXIT_BUDGET_MS, TimeUnit.MILLISECONDS), "release must end the pause within 1 s")
        assertTrue(outcome.thrown.get() == null, "a released pause returns normally: ${outcome.thrown.get()}")
        assertFalse(outcome.interruptedAfter.get(), "a release must not set the pausing thread's interrupt flag")
    }

    @Test
    fun aPauseAfterReleaseReturnsAtOnceUntilReset() {
        val pacing = ScanPacing()
        pacing.release()

        val releasedMs = timed { pacing.pause(LONG_PAUSE_MS) }
        assertTrue(releasedMs < QUICK_MS, "after release a pause returns at once; took ${releasedMs}ms")

        pacing.reset()
        val resetMs = timed { pacing.pause(SHORT_PAUSE_MS) }
        assertTrue(
            resetMs >= SHORT_PAUSE_FLOOR_MS,
            "after reset a pause waits its full delay again; took ${resetMs}ms of $SHORT_PAUSE_MS",
        )
    }

    @Test
    fun anInterruptEndsAPauseWithInterruptedException() {
        val pacing = ScanPacing()
        val outcome = PausingThread(pacing, LONG_PAUSE_MS).start()

        outcome.awaitEntered()
        outcome.thread.interrupt()

        assertTrue(outcome.finished.await(EXIT_BUDGET_MS, TimeUnit.MILLISECONDS), "an interrupt must end the pause within 1 s")
        assertTrue(
            outcome.thrown.get() is InterruptedException,
            "an interrupt surfaces as InterruptedException, so the D-02 catch arms see it: ${outcome.thrown.get()}",
        )
    }

    @Test
    fun anAlreadyInterruptedCallerThrowsAtOnce() {
        val pacing = ScanPacing()
        assertTimeoutPreemptively(Duration.ofMillis(EXIT_BUDGET_MS)) {
            Thread.currentThread().interrupt()
            try {
                assertThrows<InterruptedException> { pacing.pause(1_000) }
            } finally {
                // Never leave the flag set on the JUnit thread, whatever pause did.
                Thread.interrupted()
            }
        }
    }

    @Test
    fun aZeroOrNegativeDelayReturnsAtOnce() {
        val pacing = ScanPacing()

        val zeroMs = timed { pacing.pause(0) }
        val negativeMs = timed { pacing.pause(-5) }

        assertTrue(zeroMs < QUICK_MS, "pause(0) returns at once; took ${zeroMs}ms")
        assertTrue(negativeMs < QUICK_MS, "pause(-5) returns at once; took ${negativeMs}ms")
        assertFalse(Thread.currentThread().isInterrupted, "a zero or negative pause sets no interrupt")
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** Milliseconds [block] took on the monotonic clock, bounded so a hung pause fails the test. */
    private fun timed(block: () -> Unit): Long {
        val start = System.nanoTime()
        assertTimeoutPreemptively(Duration.ofMillis(EXIT_BUDGET_MS)) { block() }
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
    }

    /** A daemon thread that calls `pause(delayMs)` once and records how it ended. */
    private class PausingThread(
        private val pacing: ScanPacing,
        private val delayMs: Long,
    ) {
        val entered = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val thrown = AtomicReference<Throwable?>(null)
        val interruptedAfter = AtomicBoolean(false)
        val thread =
            Thread {
                entered.countDown()
                try {
                    pacing.pause(delayMs)
                } catch (t: Throwable) {
                    thrown.set(t)
                } finally {
                    interruptedAfter.set(Thread.currentThread().isInterrupted)
                    finished.countDown()
                }
            }.apply { isDaemon = true }

        fun start(): PausingThread {
            thread.start()
            return this
        }

        /** Waits until the thread is about to pause, then gives it a moment to block in the wait. */
        fun awaitEntered() {
            assertTrue(entered.await(EXIT_BUDGET_MS, TimeUnit.MILLISECONDS), "the pausing thread must start")
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(EXIT_BUDGET_MS)
            while (thread.state != Thread.State.TIMED_WAITING && System.nanoTime() < deadline) Thread.onSpinWait()
            assertTrue(thread.state == Thread.State.TIMED_WAITING, "the pausing thread must block in the wait: ${thread.state}")
        }
    }

    private companion object {
        const val LONG_PAUSE_MS = 60_000L
        const val SHORT_PAUSE_MS = 200L
        const val SHORT_PAUSE_FLOOR_MS = 150L
        const val QUICK_MS = 100L
        const val EXIT_BUDGET_MS = 1_000L
    }
}
