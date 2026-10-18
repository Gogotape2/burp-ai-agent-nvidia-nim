package com.six2dez.burp.aiagent.backends.cli

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 34 / D-07: the opencode CLI wait is a deadline wait on process exit, not a 200 ms poll.
 *
 * Every case drives [awaitOpenCodeExit] against a real `/bin/sh` child process. The test stands in
 * for the reader thread: it completes `firstOutput` and moves `lastOutputAt` the way the reader does
 * when the CLI prints a line. Skipped on Windows, where `sh` is not available.
 */
class CliOpenCodeWaitTest {
    @BeforeEach
    fun skipOnWindows() {
        Assumptions.assumeFalse(
            System.getProperty("os.name").lowercase(Locale.ROOT).contains("win"),
            "the cases start /bin/sh child processes",
        )
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun aProcessThatExitsIsExited() {
        val process = sh("exit 0")
        try {
            val started = System.nanoTime()
            val result = awaitOpenCodeExit(process, CompletableFuture(), AtomicLong(0L), timeoutMs = 5_000)
            assertEquals(CliWait.EXITED, result)
            assertTrue(elapsedMs(started) < 5_000, "an exiting process must not wait out the wall clock")
        } finally {
            process.destroyForcibly()
        }
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun silenceAfterOutputIsIdleKilled() {
        val process = sh("sleep 30")
        try {
            val firstOutput = CompletableFuture<Unit>()
            val lastOutputAt = AtomicLong(System.currentTimeMillis())
            firstOutput.complete(Unit)
            val started = System.nanoTime()
            val result = awaitOpenCodeExit(process, firstOutput, lastOutputAt, timeoutMs = 10_000, idleTimeoutMs = 300)
            assertEquals(CliWait.IDLE_KILLED, result)
            assertTrue(elapsedMs(started) < 3_000, "the idle kill must fire near the idle deadline")
            assertTrue(process.waitFor(2, TimeUnit.SECONDS), "an idle-killed process must be gone")
            assertFalse(process.isAlive)
        } finally {
            process.destroyForcibly()
        }
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun outputKeepsTheIdleDeadlineMoving() {
        val process = sh("sleep 30")
        val firstOutput = CompletableFuture<Unit>()
        val lastOutputAt = AtomicLong(System.currentTimeMillis())
        firstOutput.complete(Unit)
        val started = System.nanoTime()
        val feeder =
            Thread {
                try {
                    repeat(FEED_TICKS) {
                        Thread.sleep(FEED_INTERVAL_MS)
                        lastOutputAt.set(System.currentTimeMillis())
                    }
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        try {
            feeder.start()
            val result = awaitOpenCodeExit(process, firstOutput, lastOutputAt, timeoutMs = 8_000, idleTimeoutMs = 400)
            val elapsed = elapsedMs(started)
            assertEquals(CliWait.IDLE_KILLED, result)
            assertTrue(elapsed >= 1_300, "output must re-arm the idle deadline; the kill came after ${elapsed}ms")
            assertTrue(elapsed < 4_000, "the kill must follow the last output by about the idle timeout; took ${elapsed}ms")
        } finally {
            feeder.interrupt()
            process.destroyForcibly()
        }
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun theWallClockTimesOut() {
        val process = sh("sleep 30")
        try {
            val started = System.nanoTime()
            val result = awaitOpenCodeExit(process, CompletableFuture(), AtomicLong(0L), timeoutMs = 300)
            assertEquals(CliWait.TIMED_OUT, result)
            assertTrue(elapsedMs(started) < 3_000, "the wall-clock deadline must end the wait")
        } finally {
            // The caller's shared timeout branch destroys the process; the test does it here.
            process.destroyForcibly()
        }
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun anInterruptEndsTheWait() {
        val process = sh("sleep 30")
        val thrown = AtomicReference<Throwable?>()
        val waiting = CountDownLatch(1)
        val done = CountDownLatch(1)
        val waiter =
            Thread {
                try {
                    waiting.countDown()
                    awaitOpenCodeExit(process, CompletableFuture(), AtomicLong(0L), timeoutMs = 20_000)
                } catch (t: Throwable) {
                    thrown.set(t)
                } finally {
                    done.countDown()
                }
            }
        try {
            waiter.start()
            assertTrue(waiting.await(2, TimeUnit.SECONDS))
            // Let the waiter reach its blocking wait before the interrupt.
            Thread.sleep(INTERRUPT_SETTLE_MS)
            waiter.interrupt()
            assertTrue(done.await(1, TimeUnit.SECONDS), "an interrupt must end the wait within 1 s")
            val error = thrown.get()
            assertNotNull(error, "the interrupted wait must throw")
            assertTrue(error is InterruptedException, "expected InterruptedException, got $error")
        } finally {
            process.destroyForcibly()
        }
    }

    private fun sh(script: String): Process = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true).start()

    private fun elapsedMs(startedNanos: Long): Long = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)

    private companion object {
        const val FEED_TICKS = 10
        const val FEED_INTERVAL_MS = 100L
        const val INTERRUPT_SETTLE_MS = 200L
    }
}
