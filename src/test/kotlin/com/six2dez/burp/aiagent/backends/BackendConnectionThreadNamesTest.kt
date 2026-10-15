package com.six2dez.burp.aiagent.backends

import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackend
import com.six2dez.burp.aiagent.backends.burpai.BurpAiBackend
import com.six2dez.burp.aiagent.backends.http.RecordedRequest
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.backends.http.TestTransports
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackend
import com.six2dez.burp.aiagent.backends.ollama.OllamaBackend
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Phase 33 / LIFE-03 / D-11 — every HTTP and AI backend runs its connection work on one daemon thread
 * named `burp-ai-agent-<backendId>-connection` (`burp-ai-agent-burp-ai-connection` for Burp AI), built
 * by `ExtensionThreads.singleThread`, so a Burp thread dump attributes every backend worker to this
 * extension and none of them holds extension unload open.
 *
 * The worker is observed where the work really runs: [RecordingMontoya]'s responder runs on the thread
 * that called `Http.sendRequest`, and the Burp AI prompt stub runs on the thread that called
 * `prompt().execute`. Each per-backend send starts on a NON-daemon thread, because a thread inherits
 * its creator's daemon flag and only an explicit `isDaemon = true` makes the worker daemon.
 *
 * Phase 33 EDT-01 / SC5: an Ollama send started on the Event Dispatch Thread still runs its
 * `/api/show` model call (Phase 31 D-08) and its `/api/chat` call on the connection worker, never on
 * the EDT and never through the transport's `burp-ai-agent-http-offedt` offload thread.
 */
class BackendConnectionThreadNamesTest {
    private val recording = RecordingMontoya()
    private val connections = CopyOnWriteArrayList<AgentConnection>()

    /** Every request that reached Burp's HTTP stack, with the thread that sent it. */
    private val observed = CopyOnWriteArrayList<Pair<String, ObservedThread>>()

    private data class ObservedThread(
        val name: String,
        val daemon: Boolean,
    )

    init {
        recording.responder = { request ->
            observed += request.url to currentThread()
            answer(request)
        }
    }

    @AfterEach
    fun tearDown() {
        connections.forEach { runCatching { it.stop() } }
        recording.close()
    }

    @Test
    fun ollamaConnectionWorkerIsNamedAndDaemon() {
        val connection =
            launch(OllamaBackend(), "ollama", baseUrl = OLLAMA_URL, model = "llama3.1", contextWindow = OLLAMA_WINDOW)

        assertNull(sendFromNonDaemonThread(connection))

        assertEveryRequestRanOn("burp-ai-agent-ollama-connection", expectedUrls = listOf(OLLAMA_CHAT_URL))
    }

    @Test
    fun anthropicConnectionWorkerIsNamedAndDaemon() {
        val connection =
            launch(
                AnthropicBackend(),
                "anthropic",
                model = "claude-sonnet-4-6",
                headers = mapOf("x-api-key" to "k", "anthropic-version" to "2023-06-01"),
            )

        assertNull(sendFromNonDaemonThread(connection))

        assertEveryRequestRanOn("burp-ai-agent-anthropic-connection", expectedUrls = listOf(ANTHROPIC_URL))
    }

    @Test
    fun lmStudioConnectionWorkerIsNamedAndDaemon() {
        val connection = launch(LmStudioBackend(), "lmstudio", baseUrl = LMSTUDIO_URL, model = "local-model")

        assertNull(sendFromNonDaemonThread(connection))

        assertEveryRequestRanOn("burp-ai-agent-lmstudio-connection", expectedUrls = listOf("$LMSTUDIO_URL/v1/chat/completions"))
    }

    @Test
    fun openAiCompatibleConnectionWorkerIsNamedAfterItsBackendIdAndDaemon() {
        val backend = OpenAiCompatibleBackend(id = "openai-compatible", displayName = "OpenAI-compatible")
        val connection = launch(backend, "openai-compatible", baseUrl = OPENAI_URL, model = "gpt-4o")

        assertNull(sendFromNonDaemonThread(connection))

        assertEveryRequestRanOn(
            "burp-ai-agent-openai-compatible-connection",
            expectedUrls = listOf("$OPENAI_URL/chat/completions"),
        )
    }

    @Test
    fun burpAiConnectionWorkerIsNamedAndDaemonAndCarriesNoSessionId() {
        val executedOn = AtomicReference<ObservedThread?>(null)
        stubBurpAiPrompt(executedOn)
        val connection =
            BurpAiBackend(recording.api).launch(
                BackendLaunchConfig(
                    backendId = BURP_AI,
                    displayName = "Burp AI (built-in)",
                    sessionId = SESSION_ID,
                    transport = TestTransports.open(recording.api, BURP_AI),
                ),
            )
        connections += connection

        assertNull(sendFromNonDaemonThread(connection))

        val worker = executedOn.get()
        assertEquals("burp-ai-agent-burp-ai-connection", worker?.name, "the Burp AI prompt must run on the named worker")
        assertTrue(worker?.daemon == true, "the Burp AI worker must be daemon")
        assertFalse(worker?.name.orEmpty().contains(SESSION_ID), "the thread name must not carry the chat session id")
        assertEquals(0, recording.sendCount(), "Burp AI sends no HTTP request")
    }

    /**
     * Phase 33 EDT-01 / SC5: the send starts on the EDT, but the model calls run on the connection
     * worker. The test only STARTS the send on the EDT and waits for it off the EDT, so it never blocks
     * the EDT itself.
     */
    @Test
    fun anOllamaSendStartedOnTheEdtRunsApiShowOnTheConnectionWorker() {
        val connection = launch(OllamaBackend(), "ollama", baseUrl = OLLAMA_URL, model = "llama3.1", contextWindow = null)
        val error = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        val startedOnEdt = AtomicBoolean(false)

        SwingUtilities.invokeAndWait {
            startedOnEdt.set(SwingUtilities.isEventDispatchThread())
            connection.send(
                text = "hello",
                onChunk = {},
                onComplete = { err ->
                    error.set(err)
                    done.countDown()
                },
                jsonMode = false,
            )
        }

        assertTrue(startedOnEdt.get(), "the send must start on the EDT")
        assertTrue(done.await(SEND_TIMEOUT_SECONDS, TimeUnit.SECONDS), "send() did not complete in ${SEND_TIMEOUT_SECONDS}s")
        assertNull(error.get())
        assertEveryRequestRanOn("burp-ai-agent-ollama-connection", expectedUrls = listOf(OLLAMA_SHOW_URL, OLLAMA_CHAT_URL))
        assertTrue(
            Thread.getAllStackTraces().keys.none { it.name == OFFEDT_THREAD },
            "the model call must never fall back to the transport's EDT offload thread",
        )
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun currentThread(): ObservedThread = Thread.currentThread().let { ObservedThread(it.name, it.isDaemon) }

    @Suppress("LongParameterList") // test launcher: every argument is a BackendLaunchConfig field
    private fun launch(
        backend: AiBackend,
        backendId: String,
        baseUrl: String? = null,
        model: String,
        headers: Map<String, String> = emptyMap(),
        contextWindow: Int? = null,
    ): AgentConnection {
        val connection =
            backend.launch(
                BackendLaunchConfig(
                    backendId = backendId,
                    displayName = backendId,
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

    /** Sends one message from a fresh NON-daemon thread and waits for completion. */
    private fun sendFromNonDaemonThread(connection: AgentConnection): Throwable? {
        val error = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        val sender =
            Thread {
                connection.send(
                    text = "hello",
                    history = null,
                    onChunk = {},
                    onComplete = { err ->
                        error.set(err)
                        done.countDown()
                    },
                    jsonMode = false,
                )
            }
        sender.isDaemon = false
        sender.start()
        sender.join(TimeUnit.SECONDS.toMillis(SEND_TIMEOUT_SECONDS))
        assertTrue(done.await(SEND_TIMEOUT_SECONDS, TimeUnit.SECONDS), "send() did not complete in ${SEND_TIMEOUT_SECONDS}s")
        return error.get()
    }

    private fun assertEveryRequestRanOn(
        expectedName: String,
        expectedUrls: List<String>,
    ) {
        assertEquals(expectedUrls, observed.map { it.first }, "the requests that reached Burp's HTTP stack")
        observed.forEach { (url, thread) ->
            assertEquals(expectedName, thread.name, "$url must run on the named connection worker")
            assertTrue(thread.daemon, "$url ran on a non-daemon thread")
        }
    }

    private fun stubBurpAiPrompt(executedOn: AtomicReference<ObservedThread?>) {
        val response = Mockito.mock(PromptResponse::class.java)
        whenever(response.content()).thenReturn("burp-ai answer")
        val prompt =
            Mockito.mock(
                Prompt::class.java,
                Answer { inv ->
                    if (inv.method.name == "execute") {
                        executedOn.set(currentThread())
                        response
                    } else {
                        Answers.RETURNS_DEFAULTS.answer(inv)
                    }
                },
            )
        whenever(recording.api.ai().prompt()).thenReturn(prompt)
    }

    private fun answer(request: RecordedRequest): Pair<Int, String> =
        when {
            request.url == OLLAMA_SHOW_URL -> 200 to OLLAMA_SHOW_BODY
            request.url == OLLAMA_CHAT_URL -> 200 to OLLAMA_CHAT_BODY
            request.url == ANTHROPIC_URL -> 200 to ANTHROPIC_BODY
            request.url.endsWith("/chat/completions") -> 200 to COMPLETION_BODY
            else -> 404 to "unexpected ${request.url}"
        }

    private companion object {
        const val BURP_AI = "burp-ai"
        const val SESSION_ID = "chat-session-7f3a"
        const val OFFEDT_THREAD = "burp-ai-agent-http-offedt"
        const val SEND_TIMEOUT_SECONDS = 10L
        const val OLLAMA_WINDOW = 4096

        const val OLLAMA_URL = "http://127.0.0.1:11434"
        const val OLLAMA_SHOW_URL = "$OLLAMA_URL/api/show"
        const val OLLAMA_CHAT_URL = "$OLLAMA_URL/api/chat"
        const val LMSTUDIO_URL = "http://127.0.0.1:1234"
        const val OPENAI_URL = "http://127.0.0.1:8000/v1"
        const val ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

        const val OLLAMA_SHOW_BODY = """{"model_info":{"general.architecture":"llama","llama.context_length":32768}}"""
        const val OLLAMA_CHAT_BODY = """{"message":{"role":"assistant","content":"ok"},"prompt_eval_count":3,"eval_count":1}"""
        const val ANTHROPIC_BODY =
            """{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],""" +
                """"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"""
        const val COMPLETION_BODY = """{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"""
    }
}
