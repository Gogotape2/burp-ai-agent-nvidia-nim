package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor.StartWait
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Phase 34 / D-01..D-03 (LOOP-01) — every way a start already in progress can end has a pinned answer
 * from [AgentSupervisor.awaitStartInProgress]: ready, failed (launch throws), stopped, timed out, unload
 * (during or before the wait), interrupted, and no start at all.
 *
 * A real supervisor runs over a fake backend whose launch blocks on a latch (and throws on release when
 * asked to). Timing bounds are generous: they prove "at once" against the 10 s passive deadline, not an
 * exact latency. Every cross-thread wait is a latch or a future with a failsafe.
 */
class SessionReadySignalTest {
    private val releaseLaunch = CountDownLatch(1)
    private val supervisors = CopyOnWriteArrayList<AgentSupervisor>()
    private val workers = CopyOnWriteArrayList<Thread>()
    private val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    @AfterEach
    fun tearDown() {
        releaseLaunch.countDown()
        workers.forEach { it.interrupt() }
        supervisors.forEach { runCatching { it.shutdown() } }
    }

    @Test
    fun noStartInProgressReturnsNull() {
        val supervisor = newSupervisor(throwOnRelease = false)

        assertNull(supervisor.awaitStartInProgress(10_000), "an idle supervisor has nothing to wait for")
    }

    @Test
    fun aStartThatReachesRunningIsReady() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)
        val result = inBackground { supervisor.awaitStartInProgress(5_000) }

        assertStillWaiting(result)
        releaseLaunch.countDown()

        assertEquals(StartWait.READY, result.get(1, TimeUnit.SECONDS))
        assertNotNull(supervisor.currentSessionId(), "a READY answer means the session is already Running")
    }

    @Test
    fun aStartWhoseLaunchThrowsIsFailed() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = true)
        val result = inBackground { supervisor.awaitStartInProgress(5_000) }

        assertStillWaiting(result)
        releaseLaunch.countDown()

        assertEquals(StartWait.FAILED, result.get(1, TimeUnit.SECONDS))
    }

    @Test
    fun aStartCancelledByStopIsFailed() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)
        val result = inBackground { supervisor.awaitStartInProgress(5_000) }

        assertStillWaiting(result)
        supervisor.stop()

        assertEquals(StartWait.FAILED, result.get(1, TimeUnit.SECONDS))
    }

    @Test
    fun aStartThatOutlivesTheDeadlineTimesOut() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)

        val startNs = System.nanoTime()
        val answer = supervisor.awaitStartInProgress(200)
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs)

        assertEquals(StartWait.TIMEOUT, answer)
        assertTrue(elapsedMs >= 150, "the wait lasts until its deadline (took $elapsedMs ms)")
    }

    @Test
    fun beginShutdownEndsTheWaitAtOnce() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)
        val result = inBackground { supervisor.awaitStartInProgress(10_000) }

        assertStillWaiting(result)
        supervisor.beginShutdown()

        assertEquals(StartWait.UNLOADING, result.get(1, TimeUnit.SECONDS))
    }

    @Test
    fun afterUnloadBeganTheAnswerIsUnloadingWithoutWaiting() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)
        supervisor.beginShutdown()

        val startNs = System.nanoTime()
        val answer = supervisor.awaitStartInProgress(10_000)
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs)

        assertEquals(StartWait.UNLOADING, answer)
        assertTrue(elapsedMs < 100, "no wait once unload began (took $elapsedMs ms)")
    }

    @Test
    fun anInterruptedWaiterIsInterruptedAndKeepsItsFlag() {
        val supervisor = supervisorWithBlockedLaunch(throwOnRelease = false)
        val flagAfter = CompletableFuture<Boolean>()
        val result =
            inBackground {
                supervisor.awaitStartInProgress(10_000).also {
                    flagAfter.complete(Thread.currentThread().isInterrupted)
                }
            }

        assertStillWaiting(result)
        workers.last().interrupt()

        assertEquals(StartWait.INTERRUPTED, result.get(1, TimeUnit.SECONDS))
        assertTrue(flagAfter.get(1, TimeUnit.SECONDS), "the waiter keeps its interrupt flag")
    }

    // --- Helpers --------------------------------------------------------------------------------

    private fun newSupervisor(throwOnRelease: Boolean): AgentSupervisor = newSupervisor(throwOnRelease, CountDownLatch(1))

    private fun newSupervisor(
        throwOnRelease: Boolean,
        inLaunch: CountDownLatch,
    ): AgentSupervisor {
        val backend =
            FakeBackend {
                inLaunch.countDown()
                assertTrue(releaseLaunch.await(BLOCK_SECONDS, TimeUnit.SECONDS), "failsafe: launch never released")
                check(!throwOnRelease) { "fake launch failure" }
            }
        val registry = mock<BackendRegistry>()
        whenever(registry.get(FAKE_ID)).thenReturn(backend)
        return AgentSupervisor(api, registry, mock<AuditLogger>(), ALLOW_ALL).also {
            it.applySettings(TestSettings.baselineSettings(FAKE_ID))
            supervisors += it
        }
    }

    /** A supervisor with a start in progress: a background thread is blocked inside launch. */
    private fun supervisorWithBlockedLaunch(throwOnRelease: Boolean): AgentSupervisor {
        val inLaunch = CountDownLatch(1)
        val supervisor = newSupervisor(throwOnRelease, inLaunch)
        inBackground { supervisor.startOrAttach(FAKE_ID) }
        assertTrue(inLaunch.await(WAIT_SECONDS, TimeUnit.SECONDS), "the start reached launch")
        return supervisor
    }

    private fun <T> inBackground(block: () -> T): CompletableFuture<T> {
        val future = CompletableFuture<T>()
        val worker =
            Thread {
                try {
                    future.complete(block())
                } catch (e: Throwable) {
                    future.completeExceptionally(e)
                }
            }
        worker.isDaemon = true
        workers += worker
        worker.start()
        return future
    }

    private fun assertStillWaiting(result: CompletableFuture<*>) {
        assertThrows(TimeoutException::class.java, {
            result.get(STILL_WAITING_MS, TimeUnit.MILLISECONDS)
        }, "the waiter must still be waiting on the start in progress")
    }

    /** A connection that is alive until stopped and answers nothing. */
    private class IdleConnection : AgentConnection {
        @Volatile
        private var stopped = false

        override fun isAlive(): Boolean = !stopped

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) {
            onComplete(null)
        }

        override fun stop() {
            stopped = true
        }
    }

    /** A backend whose launch runs [onLaunch] (block, then maybe throw) before it returns a connection. */
    private class FakeBackend(
        private val onLaunch: () -> Unit,
    ) : AiBackend {
        override val id: String = FAKE_ID
        override val displayName: String = "Ready-signal fake"

        override fun launch(config: BackendLaunchConfig): AgentConnection {
            onLaunch()
            return IdleConnection()
        }
    }

    private companion object {
        const val FAKE_ID = "ready-signal-fake"
        const val WAIT_SECONDS = 10L
        const val BLOCK_SECONDS = 20L
        const val STILL_WAITING_MS = 300L

        val ALLOW_ALL =
            object : AiAccessPolicy {
                override fun refusal(
                    backendId: String,
                    burpAiEnabled: Boolean,
                ): String? = null
            }
    }
}
