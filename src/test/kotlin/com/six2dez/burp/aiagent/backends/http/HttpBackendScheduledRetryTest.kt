package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackend
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackend
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 34 / LOOP-01 / D-06 — the retry behaviour of an HTTP backend connection, pinned on the real
 * OpenAI-compatible connection (which the NVIDIA NIM and Perplexity backends reuse) through a mocked
 * Burp HTTP stack.
 *
 * Written before the backoff moved from a sleeping connection worker to a scheduled task, and green
 * on both: the attempt count, the delays, the retry events, the stop-during-backoff outcome and the
 * FIFO order of turns on one connection must not change when the mechanism does.
 *
 * Plan 34-07 adds one case per remaining HTTP backend (Ollama, Anthropic, LM Studio): each keeps its
 * own retry label on the first retry event, and a stop at that event cancels the retry.
 */
class HttpBackendScheduledRetryTest {
    private val recording = RecordingMontoya()
    private val connections = CopyOnWriteArrayList<AgentConnection>()
    private val savedRetryHook = BackendDiagnostics.retry

    @AfterEach
    fun tearDown() {
        BackendDiagnostics.retry = savedRetryHook
        connections.forEach { runCatching { it.stop() } }
        recording.close()
    }

    @Test
    fun openAiCompatibleKeepsItsRetryScheduleThenOpensTheCircuit() {
        recording.responder = { error("connection refused") }
        val events = CopyOnWriteArrayList<BackendDiagnostics.RetryEvent>()
        val connection = launch()
        try {
            BackendDiagnostics.retry = { if (it.backendId == BACKEND_ID) events += it }

            // Waits through the real 8 s backoff once, on purpose: the before/after equivalence proof.
            val outcome = Turn().also { it.sendOn(connection, "schedule-marker") }
            val error = outcome.await(SCHEDULE_TIMEOUT_SECONDS)

            assertNotNull(error, "the turn ends with an error")
            assertTrue(error!!.message.orEmpty().contains("circuit open"), "the sixth attempt fails fast: ${error.message}")
            assertEquals(5, recording.sendCount(), "five requests reach the provider before the circuit opens")
            assertEquals(
                listOf(1 to 500L, 2 to 1000L, 3 to 1500L, 4 to 2000L, 5 to 3000L),
                events.map { it.attempt to it.delayMs },
                "the retry events, in order",
            )
            assertTrue(events.all { it.backendId == BACKEND_ID }, "every retry event carries the backend id")
            assertEquals(1, outcome.completions.get(), "onComplete runs once")
        } finally {
            BackendDiagnostics.retry = savedRetryHook
        }
    }

    @Test
    fun aStopDuringTheBackoffCompletesTheTurnWithTheLastErrorAndSendsNothingMore() {
        recording.responder = { error("connection refused") }
        val firstRetry = CountDownLatch(1)
        val connection = launch()
        try {
            BackendDiagnostics.retry = { if (it.backendId == BACKEND_ID) firstRetry.countDown() }

            val outcome = Turn().also { it.sendOn(connection, "stop-marker") }
            assertTrue(firstRetry.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the first retry was never scheduled")
            connection.stop()

            val error = outcome.await(AWAIT_SECONDS)
            assertNotNull(error, "a stopped turn ends with its last error")
            assertTrue(error!!.message.orEmpty().contains("connection refused"), "the last error is delivered: ${error.message}")
            assertFalse(outcome.quietFor(QUIET_MS), "onComplete runs exactly once")
            assertEquals(1, outcome.completions.get(), "onComplete runs exactly once")
            assertEquals(1, recording.sendCount(), "no retry reaches the provider after the stop")
        } finally {
            BackendDiagnostics.retry = savedRetryHook
        }
    }

    @Test
    fun aTurnSubmittedDuringABackoffRunsOnlyAfterThatTurnCompletes() {
        val requestCount = AtomicInteger(0)
        recording.responder = {
            if (requestCount.incrementAndGet() == 1) error("connection refused")
            200 to COMPLETION_BODY
        }
        val firstRetry = CountDownLatch(1)
        val connection = launch()
        try {
            BackendDiagnostics.retry = { if (it.backendId == BACKEND_ID) firstRetry.countDown() }

            val turnA = Turn().also { it.sendOn(connection, MARKER_A) }
            assertTrue(firstRetry.await(AWAIT_SECONDS, TimeUnit.SECONDS), "turn A's first retry was never scheduled")
            val turnB = Turn().also { it.sendOn(connection, MARKER_B) }

            assertNull(turnA.await(AWAIT_SECONDS), "turn A succeeds on its retry")
            assertNull(turnB.await(AWAIT_SECONDS), "turn B succeeds")

            val bodies = recording.requests.map { it.body }
            assertEquals(
                listOf("A", "A", "B"),
                bodies.map(::turnOf),
                "turn B's request is sent only after turn A completed",
            )
            assertFalse(bodies[1].contains(MARKER_B), "turn A's retried request carries none of turn B's text")
            assertEquals(1, turnA.completions.get(), "turn A completes once")
            assertEquals(1, turnB.completions.get(), "turn B completes once")
        } finally {
            BackendDiagnostics.retry = savedRetryHook
        }
    }

    @Test
    fun ollamaSchedulesItsRetryAndStopCancelsIt() {
        // A non-default context window, so the connection sends no /api/show before the chat request.
        val connection =
            launchOn(OllamaBackend(), "ollama", baseUrl = OLLAMA_URL, model = "llama3.1", contextWindow = OLLAMA_WINDOW)

        assertAStopAtTheFirstRetryCancelsIt(connection, "ollama")
        assertTrue(recording.requests.all { it.url == "$OLLAMA_URL/api/chat" }, "only /api/chat was requested")
    }

    @Test
    fun anthropicSchedulesItsRetryAndStopCancelsIt() {
        val connection =
            launchOn(
                AnthropicBackend(),
                "anthropic",
                model = "claude-sonnet-4-6",
                headers = mapOf("x-api-key" to "k", "anthropic-version" to "2023-06-01"),
            )

        assertAStopAtTheFirstRetryCancelsIt(connection, "anthropic")
    }

    @Test
    fun lmStudioSchedulesItsRetryAndStopCancelsIt() {
        val connection = launchOn(LmStudioBackend(), "lmstudio", baseUrl = LMSTUDIO_URL, model = "local-model")

        assertAStopAtTheFirstRetryCancelsIt(connection, "lmstudio")
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun launch(): AgentConnection =
        launchOn(
            OpenAiCompatibleBackend(id = BACKEND_ID, displayName = DISPLAY_NAME),
            BACKEND_ID,
            baseUrl = OPENAI_URL,
            model = "test-model",
            displayName = DISPLAY_NAME,
        )

    @Suppress("LongParameterList") // test launcher: every argument is a BackendLaunchConfig field
    private fun launchOn(
        backend: AiBackend,
        backendId: String,
        baseUrl: String? = null,
        model: String,
        displayName: String = backendId,
        headers: Map<String, String> = emptyMap(),
        contextWindow: Int? = null,
    ): AgentConnection {
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = displayName,
                    baseUrl = baseUrl,
                    model = model,
                    headers = headers,
                    requestTimeoutSeconds = 30L,
                    contextWindow = contextWindow,
                    transport = TestTransports.open(recording.api, backendId),
                ),
            )
        connections += connection
        return connection
    }

    /**
     * Every request is refused; the first retry event must carry [retryLabel], attempt 1 and 500 ms. A
     * stop at that event completes the turn once with the refusal, and no retry is sent after it.
     */
    private fun assertAStopAtTheFirstRetryCancelsIt(
        connection: AgentConnection,
        retryLabel: String,
    ) {
        recording.responder = { error("connection refused") }
        val firstEvent = AtomicReference<BackendDiagnostics.RetryEvent?>(null)
        val firstRetry = CountDownLatch(1)
        try {
            BackendDiagnostics.retry = { event ->
                if (event.backendId == retryLabel && firstEvent.compareAndSet(null, event)) {
                    firstRetry.countDown()
                }
            }

            val outcome = Turn().also { it.sendOn(connection, "$retryLabel-stop-marker") }
            assertTrue(firstRetry.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the first $retryLabel retry was never scheduled")
            connection.stop()

            val event = firstEvent.get()
            assertEquals(Triple(retryLabel, 1, 500L), Triple(event?.backendId, event?.attempt, event?.delayMs), "the first retry event")
            val error = outcome.await(AWAIT_SECONDS)
            assertNotNull(error, "a stopped turn ends with its last error")
            assertTrue(error!!.message.orEmpty().contains("connection refused"), "the last error is delivered: ${error.message}")
            assertFalse(outcome.quietFor(QUIET_MS), "onComplete runs exactly once")
            assertEquals(1, outcome.completions.get(), "onComplete runs exactly once")
            assertEquals(1, recording.sendCount(), "no retry reaches the provider after the stop")
        } finally {
            BackendDiagnostics.retry = savedRetryHook
        }
    }

    /** Which turn a request body belongs to; turn B's body also carries turn A as history. */
    private fun turnOf(body: String): String =
        when {
            body.contains(MARKER_B) -> "B"
            body.contains(MARKER_A) -> "A"
            else -> "?"
        }

    /** One turn's outcome: every onComplete call is counted, the first error is kept. */
    private class Turn {
        val completions = AtomicInteger(0)
        private val error = AtomicReference<Throwable?>(null)
        private val done = CountDownLatch(1)
        private val second = CountDownLatch(1)

        fun sendOn(
            connection: AgentConnection,
            text: String,
        ) {
            connection.send(
                text = text,
                history = null,
                onChunk = {},
                onComplete = { err ->
                    if (completions.incrementAndGet() == 1) {
                        error.set(err)
                        done.countDown()
                    } else {
                        second.countDown()
                    }
                },
                jsonMode = false,
            )
        }

        fun await(seconds: Long): Throwable? {
            assertTrue(done.await(seconds, TimeUnit.SECONDS), "the turn did not complete in ${seconds}s")
            return error.get()
        }

        /** True when a second onComplete arrived within [millis]. */
        fun quietFor(millis: Long): Boolean = second.await(millis, TimeUnit.MILLISECONDS)
    }

    private companion object {
        const val BACKEND_ID = "openai-compatible"
        const val DISPLAY_NAME = "OpenAI-compatible"
        const val OPENAI_URL = "http://127.0.0.1:8000/v1"
        const val OLLAMA_URL = "http://127.0.0.1:11434"
        const val OLLAMA_WINDOW = 4096
        const val LMSTUDIO_URL = "http://127.0.0.1:1234"
        const val MARKER_A = "turn-A-marker"
        const val MARKER_B = "turn-B-marker"
        const val AWAIT_SECONDS = 10L
        const val SCHEDULE_TIMEOUT_SECONDS = 30L

        // Longer than the first 500 ms delay, so a retry that survived the stop would have been sent.
        const val QUIET_MS = 1_500L
        const val COMPLETION_BODY = """{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"""
    }
}
