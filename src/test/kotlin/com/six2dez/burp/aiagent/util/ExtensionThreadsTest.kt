package com.six2dez.burp.aiagent.util

import com.six2dez.burp.aiagent.ui.OffEdtDispatch
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * LIFE-03 / D-11 — the behavioural suite for [ExtensionThreadPools] and the process-wide [ExtensionThreads].
 *
 * Every thread the extension starts must be a daemon named `burp-ai-agent-<subsystem>[-N]`, built in one
 * place. The cases below pin the four LIFE-03 edge rows: adjacency (two pools of one subsystem each count
 * from 1), empty / privacy (a blank, prefixed or non-label subsystem is rejected), ordering (numbers follow
 * creation order with no gap or repeat) and concurrency (800 concurrent creations yield 800 distinct
 * numbers).
 *
 * Tracking cases use a private [ExtensionThreadPools] instance so this suite never touches the shared
 * object a production unload sweeps. Waits are bounded by [assertTimeoutPreemptively]; no case compares
 * an elapsed duration to a threshold.
 */
class ExtensionThreadsTest {
    /** Runs [block] on a fresh NON-daemon thread (the EDT is non-daemon) and returns its result. */
    private fun <T> onNonDaemonThread(block: () -> T): T {
        val result = AtomicReference<Result<T>>()
        val creator = Thread { result.set(runCatching(block)) }
        creator.isDaemon = false
        creator.start()
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) { creator.join() }
        return result.get().getOrThrow()
    }

    @Test
    fun numberedFactoryNamesEachThreadAndMakesItDaemonEvenFromANonDaemonCreator() {
        val threads =
            onNonDaemonThread {
                assertFalse(Thread.currentThread().isDaemon, "precondition: the creator must be non-daemon")
                val factory = ExtensionThreads.factory("x")
                listOf(factory.newThread {}, factory.newThread {})
            }

        assertEquals(listOf("burp-ai-agent-x-1", "burp-ai-agent-x-2"), threads.map { it.name })
        assertTrue(threads.all { it.isDaemon }, "D-11: every helper thread is daemon, whatever its creator is.")
    }

    @Test
    fun unnumberedFactoryAndNewThreadUseTheBareSubsystemName() {
        val (fromFactory, fromNewThread) =
            onNonDaemonThread {
                ExtensionThreads.factory("x", numbered = false).newThread {} to ExtensionThreads.newThread("x") {}
            }

        assertEquals("burp-ai-agent-x", fromFactory.name)
        assertEquals("burp-ai-agent-x", fromNewThread.name)
        assertTrue(fromFactory.isDaemon && fromNewThread.isDaemon)
        assertEquals(Thread.State.NEW, fromNewThread.state, "newThread returns an unstarted thread.")
    }

    @Test
    fun twoFactoriesOfTheSameSubsystemEachNumberFromOne() {
        val first = ExtensionThreads.factory("adjacent")
        val second = ExtensionThreads.factory("adjacent")

        assertEquals("burp-ai-agent-adjacent-1", first.newThread {}.name)
        assertEquals("burp-ai-agent-adjacent-1", second.newThread {}.name)
        assertEquals("burp-ai-agent-adjacent-2", first.newThread {}.name)
    }

    @Test
    fun blankPrefixedOrNonLabelSubsystemsAreRejectedWithoutEchoingTheValue() {
        val rejected =
            listOf(
                "",
                "  ",
                "burp-ai-agent-x",
                "https://host:8080/a",
                "a b",
                "host:8080",
                "-leading-dash",
                "x".repeat(65),
            )
        for (subsystem in rejected) {
            val error =
                assertThrows<IllegalArgumentException>("subsystem of length ${subsystem.length} must be rejected") {
                    ExtensionThreads.factory(subsystem)
                }
            if (subsystem.isNotBlank()) {
                assertFalse(
                    error.message.orEmpty().contains(subsystem),
                    "T-33-02: the rejection message must not carry the rejected value.",
                )
            }
        }
        assertThrows<IllegalArgumentException> { ExtensionThreads.newThread("https://host/a") {} }
    }

    @Test
    fun concurrentCreationOnOneFactoryYieldsEveryNumberExactlyOnce() {
        val factory = ExtensionThreads.factory("burst")
        val names = ConcurrentLinkedQueue<String>()
        val gate = CountDownLatch(1)
        val creators =
            (1..CREATOR_THREADS).map {
                Thread {
                    gate.await()
                    repeat(CREATIONS_PER_THREAD) { names.add(factory.newThread {}.name) }
                }.apply { start() }
            }
        gate.countDown()
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) { creators.forEach { it.join() } }

        val total = CREATOR_THREADS * CREATIONS_PER_THREAD
        assertEquals(total, names.size)
        assertEquals(total, names.toSet().size, "every name must be distinct")
        val numbers = names.map { it.removePrefix("burp-ai-agent-burst-").toInt() }.toSortedSet()
        assertEquals((1..total).toSortedSet(), numbers, "numbers must be exactly 1..$total with no gap or repeat")
    }

    @Test
    fun everyBuilderRunsOnANamedDaemonThreadAndIsTracked() {
        val pools = ExtensionThreadPools()
        val single = pools.singleThread("s")
        val scheduled = pools.scheduled("t")
        val fixed = pools.fixedPool("p", 2)
        val bounded =
            pools.boundedPool(
                "b",
                1,
                2,
                1,
                TimeUnit.SECONDS,
                ArrayBlockingQueue(4),
                ThreadPoolExecutor.AbortPolicy(),
            )
        val all = listOf(single, scheduled, fixed, bounded)
        try {
            val observed = all.map { runOn(it) }

            assertEquals("burp-ai-agent-s", observed[0].first)
            assertEquals("burp-ai-agent-t", observed[1].first)
            assertTrue(observed[2].first.startsWith("burp-ai-agent-p-"), observed[2].first)
            assertTrue(observed[3].first.startsWith("burp-ai-agent-b-"), observed[3].first)
            assertTrue(observed.all { it.second }, "every pooled worker is daemon: $observed")

            val tracked = pools.trackedSnapshot()
            assertEquals(mapOf(single to "s", scheduled to "t", fixed to "p", bounded to "b"), tracked)
        } finally {
            all.forEach { it.shutdownNow() }
        }
    }

    @Test
    fun aDelayedTaskNeverRunsAfterTheScheduledPoolIsShutDown() {
        val pools = ExtensionThreadPools()
        val scheduled = pools.scheduled("t")
        val ran = AtomicBoolean(false)
        try {
            scheduled.schedule({ ran.set(true) }, 10, TimeUnit.SECONDS)
            scheduled.shutdown()
            assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
                assertTrue(
                    scheduled.awaitTermination(FAILSAFE_SECONDS, TimeUnit.SECONDS),
                    "a pending delayed task must not hold the pool open after shutdown()",
                )
            }
            assertFalse(ran.get(), "the delayed task must not run after shutdown()")
        } finally {
            scheduled.shutdownNow()
        }
    }

    @Test
    fun aTerminatedPoolIsPrunedOnTheNextRegistration() {
        val pools = ExtensionThreadPools()
        val first = pools.singleThread("first")
        first.shutdown()
        assertTrue(first.awaitTermination(FAILSAFE_SECONDS, TimeUnit.SECONDS))
        val second = pools.singleThread("second")
        try {
            assertEquals(mapOf<ExecutorService, String>(second to "second"), pools.trackedSnapshot())
        } finally {
            second.shutdownNow()
        }
    }

    @Test
    fun releaseStopsTrackingAPool() {
        val pools = ExtensionThreadPools()
        val pool = pools.fixedPool("released", 1)
        try {
            pools.release(pool)
            assertTrue(pools.trackedSnapshot().isEmpty())
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun offEdtDispatchRunsItsWorkOnAPrefixedDaemonThread() {
        assertEquals("burp-ai-agent-probe" to true, dispatchFromNonDaemon("burp-ai-agent-probe"))

        val (legacyName, legacyDaemon) = dispatchFromNonDaemon("burp-ai-dispatch-probe")
        assertTrue(legacyName.startsWith("burp-ai-agent-"), legacyName)
        assertTrue(legacyDaemon)
    }

    @Test
    fun theSharedHelperExposesTheProductPrefix() {
        assertEquals("burp-ai-agent-", ExtensionThreads.PREFIX)
    }

    /** Runs a task on [executor] and returns the worker's name and daemon flag. */
    private fun runOn(executor: ExecutorService): Pair<String, Boolean> =
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            executor
                .submit(Callable { Thread.currentThread().name to Thread.currentThread().isDaemon })
                .get(FAILSAFE_SECONDS, TimeUnit.SECONDS)
        }

    /** Calls `OffEdtDispatch.run` from a non-daemon thread and returns the worker's name and daemon flag. */
    private fun dispatchFromNonDaemon(threadName: String): Pair<String, Boolean> {
        val observed = AtomicReference<Pair<String, Boolean>>()
        val ran = CountDownLatch(1)
        onNonDaemonThread {
            OffEdtDispatch.run(
                threadName = threadName,
                label = "extension-threads-$threadName",
                logError = { },
                work = {
                    observed.set(Thread.currentThread().name to Thread.currentThread().isDaemon)
                    ran.countDown()
                },
                onEdt = { },
            )
        }
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            assertTrue(ran.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the dispatched work never ran")
        }
        return observed.get()
    }

    private companion object {
        /** Deadlock failsafe, in seconds. A bound on a hang, never a threshold the work is measured against. */
        const val FAILSAFE_SECONDS = 10L
        const val CREATOR_THREADS = 8
        const val CREATIONS_PER_THREAD = 100
    }
}
