package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * LIFE-01 / D-05 / D-09 — the behavioural suite for [ShutdownDeadline] and [ExtensionThreadPools.terminateAll].
 *
 * D-05: one monotonic unload budget shared by every step; a step waits only for what is left, and an
 * expired budget forces without waiting. D-09: silent when a component stops in time, exactly one Error
 * line naming the component when it did not or had to be forced.
 *
 * Arithmetic cases use a fake `nanoTime`. Real-time cases use budgets of a few hundred milliseconds and
 * [assertTimeoutPreemptively] bounds of several seconds: the bound catches a wait that ignored the
 * deadline (a fresh or full budget), never a few milliseconds of scheduling noise. Every executor is
 * shut down and every blocker released in `finally`.
 */
class ShutdownDeadlineTest {
    private val logged = CopyOnWriteArrayList<String>()
    private val log: (String) -> Unit = { logged.add(it) }

    /** A task that ignores interrupts until [release] opens; records that it saw one. */
    private class Blocker {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val sawInterrupt = AtomicBoolean(false)
        val task =
            Runnable {
                started.countDown()
                while (true) {
                    try {
                        release.await()
                        return@Runnable
                    } catch (_: InterruptedException) {
                        sawInterrupt.set(true)
                    }
                }
            }
    }

    /** A task that waits on [release] and stops at the first interrupt. */
    private class Interruptible {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val task =
            Runnable {
                started.countDown()
                try {
                    release.await()
                } catch (_: InterruptedException) {
                    // Stops on interrupt, which is what a well-behaved worker does.
                }
            }
    }

    @Test
    fun remainingTimeCountsDownMonotonicallyAndNeverGoesNegative() {
        var now = 5_000_000_000L
        val deadline = ShutdownDeadline(1_000, nanoTime = { now })

        assertEquals(1_000, deadline.remainingMs())
        assertFalse(deadline.expired())

        now += TimeUnit.MILLISECONDS.toNanos(600)
        assertEquals(400, deadline.remainingMs())
        assertFalse(deadline.expired())

        now += TimeUnit.MILLISECONDS.toNanos(600)
        assertEquals(0, deadline.remainingMs(), "remainingMs() never goes below 0")
        assertTrue(deadline.expired())
    }

    @Test
    fun theUnloadBudgetIsTenSeconds() {
        assertEquals(10_000L, ShutdownDeadline.UNLOAD_BUDGET_MS)
        val remaining = ShutdownDeadline.unload().remainingMs()
        assertTrue(remaining in 1..10_000L, "a fresh unload deadline starts with the whole budget: $remaining")
    }

    @Test
    fun awaitOrForceOnAStoppedExecutorReturnsTrueSilently() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            executor.shutdown()
            val stopped =
                assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                    ShutdownDeadline(1_000).awaitOrForce(executor, "idle", log)
                }
            assertTrue(stopped)
            assertEquals(emptyList<String>(), logged.toList(), "D-09: a clean stop writes nothing")
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun awaitOrForceForcesAndReportsOnceWhenTheExecutorOutlivesTheDeadline() {
        val executor = Executors.newSingleThreadExecutor()
        val blocker = Blocker()
        try {
            executor.execute(blocker.task)
            assertTrue(blocker.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            executor.shutdown()

            val stopped =
                assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                    ShutdownDeadline(100).awaitOrForce(executor, "blocker", log)
                }

            assertFalse(stopped)
            awaitTrue("the stuck task must observe the shutdownNow() interrupt") { blocker.sawInterrupt.get() }
            assertEquals(listOf("Unload: blocker did not stop before the unload deadline"), logged.toList())
        } finally {
            blocker.release.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun awaitOrForceWithAnExpiredDeadlineDoesNotWaitAndStillForcesAndReports() {
        var now = 0L
        val deadline = ShutdownDeadline(60_000, nanoTime = { now })
        now += TimeUnit.SECONDS.toNanos(61)
        val executor = Executors.newSingleThreadExecutor()
        val blocker = Blocker()
        try {
            executor.execute(blocker.task)
            assertTrue(blocker.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            executor.shutdown()

            // A wait that ignored the expired deadline would wait a minute and trip this bound.
            val stopped =
                assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                    deadline.awaitOrForce(executor, "late", log)
                }

            assertFalse(stopped)
            awaitTrue("an expired deadline must still force the executor") { blocker.sawInterrupt.get() }
            assertEquals(listOf("Unload: late did not stop before the unload deadline"), logged.toList())
        } finally {
            blocker.release.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun awaitOrForceSurvivesAThrowingLogSink() {
        val executor = Executors.newSingleThreadExecutor()
        val blocker = Blocker()
        try {
            executor.execute(blocker.task)
            assertTrue(blocker.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            executor.shutdown()
            val stopped =
                assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                    ShutdownDeadline(50).awaitOrForce(executor, "sink") { error("logger torn down") }
                }
            assertFalse(stopped)
        } finally {
            blocker.release.countDown()
            executor.shutdownNow()
        }
    }

    @Test
    fun joinOrReportIsSilentForAFinishedThreadAndReportsAStuckOne() {
        val finished = Thread {}.apply { start() }
        assertTrue(
            assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                ShutdownDeadline(1_000).joinOrReport(finished, "finished", log)
            },
        )
        assertEquals(emptyList<String>(), logged.toList())

        val release = CountDownLatch(1)
        val stuck =
            Thread {
                while (release.count > 0) {
                    runCatching { release.await() }
                }
            }.apply {
                isDaemon = true
                start()
            }
        try {
            val joined =
                assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                    ShutdownDeadline(100).joinOrReport(stuck, "joiner", log)
                }
            assertFalse(joined)
            assertEquals(listOf("Unload: joiner did not stop before the unload deadline"), logged.toList())
        } finally {
            release.countDown()
        }
    }

    @Test
    fun terminateAllForcesForgottenPoolsReportsSurvivorsSortedAndClearsTracking() {
        val pools = ExtensionThreadPools()
        val forgotten = pools.singleThread("zeta-forgotten")
        val clean = pools.singleThread("alpha-clean")
        val ownerStoppedButStuck = pools.singleThread("mid-stuck")
        val forcedAndStuck = pools.singleThread("beta-forced-stuck")
        val all = listOf(forgotten, clean, ownerStoppedButStuck, forcedAndStuck)
        val interruptible = Interruptible()
        val stuckOne = Blocker()
        val stuckTwo = Blocker()
        try {
            forgotten.execute(interruptible.task)
            ownerStoppedButStuck.execute(stuckOne.task)
            forcedAndStuck.execute(stuckTwo.task)
            assertTrue(interruptible.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            assertTrue(stuckOne.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            assertTrue(stuckTwo.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            clean.shutdown()
            ownerStoppedButStuck.shutdown()

            assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                pools.terminateAll(ShutdownDeadline(300), log)
            }

            assertEquals(
                listOf(
                    "Unload: beta-forced-stuck did not stop before the unload deadline",
                    "Unload: mid-stuck did not stop before the unload deadline",
                    "Unload: zeta-forgotten was still running at unload and was stopped",
                ),
                logged.toList(),
                "D-09: one line per forced or surviving subsystem, sorted; nothing for the clean pool",
            )
            assertTrue(all.all { it.isShutdown }, "every tracked pool is shut down after the sweep")
            assertTrue(pools.trackedSnapshot().isEmpty(), "the sweep clears the tracked set")
        } finally {
            stuckOne.release.countDown()
            stuckTwo.release.countDown()
            interruptible.release.countDown()
            all.forEach { it.shutdownNow() }
        }
    }

    @Test
    fun terminateAllOnACleanSetWritesNothing() {
        val pools = ExtensionThreadPools()
        val pool = pools.fixedPool("tidy", 1)
        pool.shutdown()
        assertTrue(pool.awaitTermination(FAILSAFE_SECONDS, TimeUnit.SECONDS))
        pools.terminateAll(ShutdownDeadline(1_000), log)
        assertEquals(emptyList<String>(), logged.toList())
    }

    @Test
    fun terminateAllInterruptedMidWaitRestoresTheFlagAndStillForcesEveryPool() {
        val pools = ExtensionThreadPools()
        val stuck = pools.singleThread("interrupt-stuck")
        val idle = pools.singleThread("interrupt-idle")
        val all: List<ExecutorService> = listOf(stuck, idle)
        val blocker = Blocker()
        val flagAfter = AtomicBoolean(false)
        try {
            stuck.execute(blocker.task)
            assertTrue(blocker.started.await(FAILSAFE_SECONDS, TimeUnit.SECONDS))
            stuck.shutdown()

            val sweeper =
                Thread {
                    Thread.currentThread().interrupt()
                    pools.terminateAll(ShutdownDeadline(ShutdownDeadline.UNLOAD_BUDGET_MS), log)
                    flagAfter.set(Thread.currentThread().isInterrupted)
                }
            sweeper.start()
            assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) { sweeper.join() }

            assertTrue(flagAfter.get(), "the interrupt flag must be restored")
            assertTrue(all.all { it.isShutdown }, "every tracked pool is forced even when interrupted")
            awaitTrue("the stuck task must observe the forced interrupt") { blocker.sawInterrupt.get() }
            assertTrue(
                logged.any { it == "Unload: interrupt-stuck did not stop before the unload deadline" },
                "the survivor is still reported: $logged",
            )
            assertTrue(pools.trackedSnapshot().isEmpty())
        } finally {
            blocker.release.countDown()
            all.forEach { it.shutdownNow() }
        }
    }

    /** Polls [condition] until true; fails with [message] after the failsafe. */
    private fun awaitTrue(
        message: String,
        condition: () -> Boolean,
    ) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(FAILSAFE_SECONDS)
        while (!condition()) {
            check(System.nanoTime() < end) { message }
            Thread.sleep(1)
        }
    }

    private companion object {
        /** Deadlock failsafe, in seconds. A bound on a hang, never a threshold the work is measured against. */
        const val FAILSAFE_SECONDS = 10L
    }
}
