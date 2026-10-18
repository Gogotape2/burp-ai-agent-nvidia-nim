package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor.StartWait
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Phase 34 / D-01..D-03 (LOOP-01) — the passive scanner no longer polls for a backend session. When
 * another thread is already starting the backend, a passive item waits on that start's ready signal
 * (at most 10 s, ended at once by unload) and is analysed when the start succeeds, instead of being
 * dropped at once by the "startup already in progress" refusal.
 *
 * The end-to-end cases run a real [AgentSupervisor] over a fake backend whose launch blocks on a latch;
 * the mocked cases pin the log line the passive scanner writes for each [StartWait] answer. Every
 * cross-thread wait is a latch or a future with a failsafe.
 */
class PassiveBackendReadyWaitTest {
    private val output: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val errors: MutableList<String> = Collections.synchronizedList(mutableListOf())
    private val releaseLaunch = CountDownLatch(1)
    private val supervisors = CopyOnWriteArrayList<AgentSupervisor>()
    private val scanners = CopyOnWriteArrayList<PassiveAiScanner>()
    private val workers = CopyOnWriteArrayList<Thread>()

    private val logging =
        mock<Logging> {
            on { logToOutput(any<String>()) } doAnswer { output += it.getArgument<String>(0) }
            on { logToError(any<String>()) } doAnswer { errors += it.getArgument<String>(0) }
        }
    private val api: MontoyaApi =
        mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also {
            whenever(it.logging()).thenReturn(logging)
        }
    private val settings: AgentSettings = TestSettings.baselineSettings(FAKE_ID)

    @AfterEach
    fun tearDown() {
        releaseLaunch.countDown()
        workers.forEach { it.interrupt() }
        scanners.forEach { runCatching { it.shutdown() } }
        supervisors.forEach { runCatching { it.shutdown() } }
    }

    // --- End to end, real supervisor ------------------------------------------------------------

    @Test
    fun anItemArrivingWhileAnotherThreadIsStartingTheBackendWaitsAndIsAnalysed() {
        val (supervisor, launching) = supervisorWithBlockedLaunch()
        val passive = scanner(supervisor)

        val result = inBackground { passive.ensureBackendRunning(settings) }

        assertStillWaiting(result)
        releaseLaunch.countDown()
        assertTrue(result.get(2, TimeUnit.SECONDS), "the item is analysed once the start in progress succeeds")
        assertTrue(launching.get(WAIT_SECONDS, TimeUnit.SECONDS), "the other thread's start succeeded")
        assertTrue(
            output.contains("[PassiveAiScanner] Backend ready: $FAKE_ID"),
            "the ready line is written, got $output",
        )
    }

    @Test
    fun beginShutdownEndsAPassiveWaitAtOnce() {
        val (supervisor, _) = supervisorWithBlockedLaunch()
        val passive = scanner(supervisor)

        val result = inBackground { passive.ensureBackendRunning(settings) }

        assertStillWaiting(result)
        val errorsBefore = errors.toList()
        supervisor.beginShutdown()
        assertFalse(result.get(1, TimeUnit.SECONDS), "unload ends the wait far below the 10 s deadline")
        assertEquals(errorsBefore, errors.toList(), "an unload-ended wait writes no Error line")
    }

    // --- Mocked supervisor: the reaction to each answer -------------------------------------------

    @Test
    fun aSuccessfulStartIsNotWaitedOn() {
        val supervisor = mockedSupervisor(started = true)
        whenever(supervisor.currentSessionId()).thenReturn(null, "session-1")

        assertTrue(scanner(supervisor).ensureBackendRunning(settings))

        verify(supervisor, never()).awaitStartInProgress(any())
        assertTrue(output.contains("[PassiveAiScanner] Backend ready: $FAKE_ID"), "got $output")
        assertEquals(emptyList<String>(), errors.toList())
    }

    @Test
    fun aTimedOutStartDropsTheItemWithOneLine() {
        val supervisor = mockedSupervisor(started = false)
        whenever(supervisor.awaitStartInProgress(any())).thenReturn(StartWait.TIMEOUT)

        assertFalse(scanner(supervisor).ensureBackendRunning(settings))

        assertEquals(listOf("[PassiveAiScanner] Backend startup in progress did not finish in time"), errors.toList())
    }

    @Test
    fun anUnloadingOrInterruptedWaitWritesNothing() {
        listOf(StartWait.UNLOADING, StartWait.INTERRUPTED).forEach { answer ->
            errors.clear()
            val supervisor = mockedSupervisor(started = false)
            whenever(supervisor.awaitStartInProgress(any())).thenReturn(answer)

            assertFalse(scanner(supervisor).ensureBackendRunning(settings), "$answer drops the item")

            assertEquals(emptyList<String>(), errors.toList(), "$answer writes no Error line")
        }
    }

    @Test
    fun aFailedOrAbsentStartKeepsTodaysLine() {
        listOf(StartWait.FAILED, null).forEach { answer ->
            errors.clear()
            val supervisor = mockedSupervisor(started = false)
            whenever(supervisor.lastStartError()).thenReturn("boom")
            // null is the unstubbed answer of a plain mock: "no start in progress".
            if (answer != null) whenever(supervisor.awaitStartInProgress(any())).thenReturn(answer)

            assertFalse(scanner(supervisor).ensureBackendRunning(settings), "$answer drops the item")

            assertEquals(listOf("[PassiveAiScanner] Failed to start backend: boom"), errors.toList(), "answer $answer")
        }
    }

    // --- Helpers --------------------------------------------------------------------------------

    /** A plain mock (an unstubbed enum answer is null) with no session and the given start answer. */
    private fun mockedSupervisor(started: Boolean): AgentSupervisor =
        mock<AgentSupervisor>().also {
            whenever(it.status()).thenReturn(AgentSupervisor.Status("Idle", null))
            whenever(it.startOrAttach(any())).thenReturn(started)
        }

    /**
     * A real supervisor whose fake backend blocks in launch until [releaseLaunch]; a background thread
     * has already entered that launch when this returns, so a start is in progress.
     */
    private fun supervisorWithBlockedLaunch(): Pair<AgentSupervisor, CompletableFuture<Boolean>> {
        val inLaunch = CountDownLatch(1)
        val backend =
            FakeBackend {
                inLaunch.countDown()
                assertTrue(releaseLaunch.await(BLOCK_SECONDS, TimeUnit.SECONDS), "failsafe: launch never released")
            }
        val registry = mock<BackendRegistry>()
        whenever(registry.get(FAKE_ID)).thenReturn(backend)
        val supervisor =
            AgentSupervisor(api, registry, mock<AuditLogger>(), ALLOW_ALL).also {
                it.applySettings(settings)
                supervisors += it
            }
        val launching = inBackground { supervisor.startOrAttach(FAKE_ID) }
        assertTrue(inLaunch.await(WAIT_SECONDS, TimeUnit.SECONDS), "the other thread's start reached launch")
        return supervisor to launching
    }

    private fun scanner(supervisor: AgentSupervisor): PassiveAiScanner = PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { settings }.also { scanners += it }

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

    private fun assertStillWaiting(result: CompletableFuture<Boolean>) {
        assertThrows(TimeoutException::class.java, {
            result.get(STILL_WAITING_MS, TimeUnit.MILLISECONDS)
        }, "the passive item must wait for the start in progress, not be dropped at once")
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

    /** A backend whose launch runs [onLaunch] (block or throw) before it returns a connection. */
    private class FakeBackend(
        private val onLaunch: () -> Unit,
    ) : AiBackend {
        override val id: String = FAKE_ID
        override val displayName: String = "Ready-wait fake"

        override fun launch(config: BackendLaunchConfig): AgentConnection {
            onLaunch()
            return IdleConnection()
        }
    }

    private companion object {
        const val FAKE_ID = "ready-wait-fake"
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
