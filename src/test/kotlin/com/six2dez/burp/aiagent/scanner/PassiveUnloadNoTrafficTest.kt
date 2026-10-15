package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
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

        val worker = f.scanner.executor.submit(Callable { Thread.currentThread() }).get(WAIT_SECONDS, TimeUnit.SECONDS)

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

    /** How the stubbed `supervisor.send` behaves once it has counted the call. */
    internal enum class SendMode {
        /** Blocks (interruptibly) until the fixture closes, like a provider that never answers. */
        BLOCK,

        /** Completes at once with an error, so a batch falls back to one send per item. */
        FAIL_FAST,
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
                    sendCalls.incrementAndGet()
                    val onComplete = invocation.getArgument<(Throwable?) -> Unit>(ON_COMPLETE_ARG)
                    when (sendMode) {
                        SendMode.BLOCK ->
                            try {
                                release.await(WAIT_SECONDS, TimeUnit.SECONDS)
                            } catch (e: InterruptedException) {
                                sendInterrupted.countDown()
                                throw e
                            }
                        SendMode.FAIL_FAST -> onComplete(IllegalStateException("stub backend error"))
                    }
                    Unit
                }
            }
        val scanner = PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { settings }

        fun outputLines(): List<String> = synchronized(output) { output.toList() }

        fun errorLines(): List<String> = synchronized(errors) { errors.toList() }

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
    }
}
