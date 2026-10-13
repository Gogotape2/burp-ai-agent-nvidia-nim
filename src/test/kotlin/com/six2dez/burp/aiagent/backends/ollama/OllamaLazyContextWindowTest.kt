package com.six2dez.burp.aiagent.backends.ollama

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.RecordedRequest
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.backends.http.TestTransports
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 31 / D-08 / GATE-02 — Ollama sends nothing at launch. Its `/api/show` context-window
 * detection runs on the connection worker before the first `/api/chat` of that connection, through
 * the connection's bound transport and therefore through the same egress gate as the chat request.
 *
 * Every request is counted on [RecordingMontoya], which records what reached Burp's HTTP stack.
 */
class OllamaLazyContextWindowTest {
    private val recording = RecordingMontoya()

    @AfterEach
    fun closeRecording() {
        recording.close()
    }

    @Test
    fun launchSendsNothing() {
        recording.responder = ::answerOllama

        launch(TestTransports.open(recording.api, "ollama"), contextWindow = null)

        assertEquals(0, recording.sendCount(), "launch() must not query the model: ${recording.requests}")
    }

    @Test
    fun theFirstSendDetectsTheWindowThenChatsWithIt() {
        recording.responder = ::answerOllama
        val connection = launch(TestTransports.open(recording.api, "ollama"), contextWindow = null)

        assertNull(sendAndAwait(connection))

        assertEquals(listOf(SHOW_URL, CHAT_URL), urls())
        assertTrue(recording.requests[0].body.contains("\"name\":\"llama3.1\""), recording.requests[0].body)
        assertTrue(recording.requests[1].body.contains("\"num_ctx\":32768"), recording.requests[1].body)
    }

    @Test
    fun aSecondSendReusesTheDetectedWindow() {
        recording.responder = ::answerOllama
        val connection = launch(TestTransports.open(recording.api, "ollama"), contextWindow = null)

        assertNull(sendAndAwait(connection))
        assertNull(sendAndAwait(connection))

        assertEquals(listOf(SHOW_URL, CHAT_URL, CHAT_URL), urls())
        assertTrue(recording.requests[2].body.contains("\"num_ctx\":32768"), recording.requests[2].body)
    }

    @Test
    fun aConfiguredNonDefaultWindowSkipsDetection() {
        recording.responder = ::answerOllama
        val connection = launch(TestTransports.open(recording.api, "ollama"), contextWindow = 4096)

        assertNull(sendAndAwait(connection))

        assertEquals(listOf(CHAT_URL), urls())
        assertTrue(recording.requests[0].body.contains("\"num_ctx\":4096"), recording.requests[0].body)
    }

    @Test
    fun aFailedDetectionFallsBackToTheConfiguredValue() {
        recording.responder = { request -> if (request.url == SHOW_URL) 404 to "not found" else answerOllama(request) }
        val unset = launch(TestTransports.open(recording.api, "ollama"), contextWindow = null)

        assertNull(sendAndAwait(unset))

        assertEquals(listOf(SHOW_URL, CHAT_URL), urls())
        assertFalse(recording.requests[1].body.contains("num_ctx"), recording.requests[1].body)

        val defaulted = launch(TestTransports.open(recording.api, "ollama"), contextWindow = DEFAULT_WINDOW)

        assertNull(sendAndAwait(defaulted))

        assertEquals(listOf(SHOW_URL, CHAT_URL, SHOW_URL, CHAT_URL), urls())
        assertTrue(recording.requests[3].body.contains("\"num_ctx\":8192"), recording.requests[3].body)
    }

    @Test
    fun aRefusedDetectionFailsTheSendAndSendsNothing() {
        recording.responder = ::answerOllama
        val connection = launch(TestTransports.refusing(recording.api, REFUSAL, "ollama"), contextWindow = null)

        val error = sendAndAwait(connection)

        assertTrue(error is AiAccessRefusedException, "Expected AiAccessRefusedException, got $error")
        assertEquals(REFUSAL, error?.message)
        assertEquals(0, recording.sendCount(), "A refused send must send nothing: ${recording.requests}")
    }

    @Test
    fun aRefusalIsNeverMemoizedAsAWindow() {
        recording.responder = ::answerOllama
        val switchable =
            MontoyaHttpTransport(recording.api) { if (recording.aiEnabled.get()) null else REFUSAL }.forBackend("ollama")
        val connection = launch(switchable, contextWindow = null)

        val refused = sendAndAwait(connection)
        assertTrue(refused is AiAccessRefusedException, "Expected AiAccessRefusedException, got $refused")
        assertEquals(0, recording.sendCount())

        recording.aiEnabled.set(true)
        assertNull(sendAndAwait(connection))

        assertEquals(listOf(SHOW_URL, CHAT_URL), urls())
        assertTrue(recording.requests[1].body.contains("\"num_ctx\":32768"), recording.requests[1].body)
    }

    @Test
    fun aMissingTransportFailsTheSendFast() {
        val connection = launch(transport = null, contextWindow = null, baseUrl = UNREACHABLE_URL)

        val error = sendAndAwait(connection)

        assertTrue(error is IllegalStateException, "Expected IllegalStateException, got $error")
        assertTrue(
            error?.message.orEmpty().contains("MontoyaHttpTransport unavailable"),
            "Expected the shared transport-unavailable message, got: ${error?.message}",
        )
    }

    private fun urls(): List<String> = recording.requests.map { it.url }

    private fun launch(
        transport: MontoyaHttpTransport?,
        contextWindow: Int?,
        baseUrl: String = BASE_URL,
    ): AgentConnection =
        OllamaBackend().launch(
            BackendLaunchConfig(
                backendId = "ollama",
                displayName = "Ollama",
                baseUrl = baseUrl,
                model = "llama3.1",
                requestTimeoutSeconds = 30L,
                contextWindow = contextWindow,
                transport = transport,
            ),
        )

    private fun sendAndAwait(connection: AgentConnection): Throwable? {
        val error = AtomicReference<Throwable?>(null)
        val done = CountDownLatch(1)
        connection.send(
            text = "hello",
            onChunk = {},
            onComplete = { err ->
                error.set(err)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(SEND_TIMEOUT_SECONDS, TimeUnit.SECONDS), "send() did not complete in ${SEND_TIMEOUT_SECONDS}s")
        return error.get()
    }

    private fun answerOllama(request: RecordedRequest): Pair<Int, String> =
        when (request.url) {
            SHOW_URL -> 200 to """{"model_info":{"general.architecture":"llama","llama.context_length":32768}}"""
            CHAT_URL -> 200 to """{"message":{"role":"assistant","content":"ok"},"prompt_eval_count":3,"eval_count":1}"""
            else -> 404 to "unexpected ${request.url}"
        }

    private companion object {
        const val BASE_URL = "http://127.0.0.1:11434"
        const val SHOW_URL = "$BASE_URL/api/show"
        const val CHAT_URL = "$BASE_URL/api/chat"

        // Port 9 (discard) is closed on test hosts, so the pre-fix direct-client path cannot reach a model.
        const val UNREACHABLE_URL = "http://127.0.0.1:9"
        const val DEFAULT_WINDOW = 8192
        const val REFUSAL = "AI request refused: Use AI is off in Burp."
        const val SEND_TIMEOUT_SECONDS = 10L
    }
}
