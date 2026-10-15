package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 / CR-01, LIFE-02 ("Unload sends no AI traffic") — once [AgentSupervisor.beginShutdown] ran,
 * no path through the supervisor puts an AI request on the wire: every entry point refuses with
 * [AgentSupervisor.UNLOADING_REFUSAL], a turn in flight (a chat session's first turn or an agent send) is
 * stopped by the latch alone, unload landing between sendChat's entry check and its send starts nothing,
 * and an HTTP backend's retry for a turn in flight is never sent.
 *
 * Every provider request is counted where it would really leave Burp ([RecordingMontoya.sendCount]);
 * Burp AI sends no HTTP request, so its `prompt().execute` calls are counted instead. Every wait is a
 * latch with a failsafe.
 */
class AgentSupervisorUnloadLatchTest {
    private val recording = RecordingMontoya()
    private val audit = mock<AuditLogger>()
    private val errors = CopyOnWriteArrayList<String>()
    private val supervisors = CopyOnWriteArrayList<AgentSupervisor>()
    private val release = CountDownLatch(1)

    init {
        whenever(recording.api.persistence().preferences()).thenReturn(InMemoryPreferences())
        // Read before doAnswer: a deep-stub call inside the stubbing chain is an unfinished stubbing.
        val logging = recording.api.logging()
        doAnswer { invocation ->
            errors += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyString())
        recording.responder = { request ->
            if (request.url.endsWith("/chat/completions")) 200 to COMPLETION else 200 to "{}"
        }
        recording.aiEnabled.set(true)
    }

    @AfterEach
    fun tearDown() {
        release.countDown()
        supervisors.forEach { runCatching { it.shutdown() } }
        recording.close()
    }

    @Test
    fun everyEntryPointRefusesOnceUnloadBegan() {
        val supervisor = newSupervisor()
        assertTrue(supervisor.startOrAttach("lmstudio"), "the agent session starts before the latch")
        val sentBefore = recording.sendCount()

        supervisor.beginShutdown()

        listOf("burp-ai", "lmstudio", "ollama").forEach { id ->
            assertEquals(AgentSupervisor.UNLOADING_REFUSAL, supervisor.aiAccessRefusal(id), "$id must be refused")
        }
        val chat = Completion()
        assertNull(chatSend(supervisor, "lmstudio", chat), "a refused chat send returns no connection")
        assertUnloadingRefusal(chat.await(), "sendChat")
        val agent = Completion()
        agentSend(supervisor, agent)
        assertUnloadingRefusal(agent.await(), "send")
        assertFalse(supervisor.startOrAttach("ollama"), "no backend starts once unload began")
        assertEquals(AgentSupervisor.UNLOADING_REFUSAL, supervisor.lastStartError())
        assertEquals(AgentSupervisor.UNLOADING_REFUSAL, supervisor.aiToolRefusal())
        assertFalse(supervisor.backendHealth(settings()).isHealthy, "a health check is refused at the transport")
        assertEquals(sentBefore, recording.sendCount(), "nothing reaches the provider after beginShutdown")
    }

    @Test
    fun aFirstTurnInFlightIsStoppedByBeginShutdownAlone() {
        val prompt = blockingBurpAiPrompt()
        val supervisor = newSupervisor()
        val first = Completion()
        chatSend(supervisor, "burp-ai", first)
        assertTrue(prompt.inFlight.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the first turn never reached execute")

        supervisor.beginShutdown()

        assertNotNull(first.await(STOP_SECONDS), "beginShutdown alone ends the turn with an error")
        assertTrue(prompt.interrupted.get(), "the turn was stopped (execute saw the interrupt)")
        assertTrue(errors.none { it.contains("AI backend error") }, "a turn the unload stopped is not an error: $errors")
        val next = Completion()
        chatSend(supervisor, "burp-ai", next)
        assertUnloadingRefusal(next.await(), "the next turn of the same chat session")
        assertEquals(1, prompt.executions.get(), "execute ran once")
    }

    @Test
    fun unloadLandingBetweenTheEntryCheckAndTheSendStartsNothing() {
        whenever(audit.isEnabled()).thenReturn(true)
        val connection = RecordingConnection()
        val supervisorRef = AtomicReference<AgentSupervisor>()
        val backend = UnloadingBackend(connection) { supervisorRef.get().beginShutdown() }
        val registry = mock<BackendRegistry>()
        whenever(registry.get(FAKE_ID)).thenReturn(backend)
        val supervisor = newSupervisor(registry).also { supervisorRef.set(it) }

        val done = Completion()
        assertNull(chatSend(supervisor, FAKE_ID, done), "the refused turn returns no connection")

        assertUnloadingRefusal(done.await(), "a turn racing the unload")
        assertEquals(0, connection.sends.get(), "the connection's send is never called")
        assertEquals(1, connection.stops.get(), "the launched connection is stopped once")
        verify(audit, never()).logEvent(eq("prompt"), any())
    }

    @Test
    fun aRetryForATurnInFlightIsNeverSentAfterUnloadBegan() {
        val supervisor = newSupervisor()
        recording.responder = {
            supervisor.beginShutdown()
            error("connection refused") // retryable for HttpBackendSupport, so today's backoff would resend
        }

        val done = Completion()
        chatSend(supervisor, "openai-compatible", done)

        assertNotNull(done.await(), "the turn completes with an error")
        assertEquals(1, recording.sendCount(), "the backoff retry never reaches the provider")
    }

    @Test
    fun anAgentSendInFlightIsStoppedAndTheNextIsRefused() {
        val prompt = blockingBurpAiPrompt()
        val supervisor = newSupervisor()
        assertTrue(supervisor.startOrAttach("burp-ai"), "the agent session starts before the latch")
        val first = Completion()
        agentSend(supervisor, first)
        assertTrue(prompt.inFlight.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the agent send never reached execute")

        supervisor.beginShutdown()

        assertNotNull(first.await(STOP_SECONDS), "beginShutdown alone ends the agent send with an error")
        assertTrue(prompt.interrupted.get(), "the agent send was stopped (execute saw the interrupt)")
        val next = Completion()
        agentSend(supervisor, next)
        assertUnloadingRefusal(next.await(), "the next agent send")
        assertEquals(1, prompt.executions.get(), "execute ran once")
    }

    @Test
    fun shutdownAloneLatches() {
        val supervisor = newSupervisor()

        supervisor.shutdown()

        assertEquals(AgentSupervisor.UNLOADING_REFUSAL, supervisor.aiAccessRefusal("burp-ai"))
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun newSupervisor(registry: BackendRegistry = BackendRegistry(recording.api)): AgentSupervisor =
        AgentSupervisor(recording.api, registry, audit, StoreAiAccessPolicy()).also {
            it.applySettings(settings())
            supervisors += it
        }

    // Every backend gets a URL, a model and an API key (ProviderEgressChokePointTest's settings).
    private fun settings(): AgentSettings =
        TestSettings.baselineSettings("lmstudio").copy(
            ollamaUrl = "http://127.0.0.1:11434",
            ollamaModel = "test-model",
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = "test-model",
            openAiCompatibleUrl = "http://127.0.0.1:8000/v1",
            openAiCompatibleModel = "test-model",
            openAiCompatibleApiKey = "test-key",
        )

    private fun chatSend(
        supervisor: AgentSupervisor,
        backendId: String,
        completion: Completion,
    ): AgentConnection? =
        supervisor.sendChat(
            chatSessionId = CHAT_SESSION,
            backendId = backendId,
            text = "hello",
            contextJson = null,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            onChunk = {},
            onComplete = completion::complete,
        )

    private fun agentSend(
        supervisor: AgentSupervisor,
        completion: Completion,
    ) {
        supervisor.send(
            text = "analyze",
            contextJson = null,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            onChunk = {},
            onComplete = completion::complete,
        )
    }

    private fun assertUnloadingRefusal(
        error: Throwable?,
        what: String,
    ) {
        assertTrue(error is AiAccessRefusedException, "$what must be refused, got $error")
        assertEquals(AgentSupervisor.UNLOADING_REFUSAL, error?.message, "$what must carry the unloading refusal")
    }

    /**
     * Burp AI's prompt (BackendConnectionThreadNamesTest's stub shape): the first `execute` blocks until
     * [release] (failsafe [BLOCK_SECONDS]) and records an interrupt; later calls answer at once.
     */
    private fun blockingBurpAiPrompt(): BlockingPrompt {
        val blocking = BlockingPrompt(release)
        whenever(recording.api.ai().prompt()).thenReturn(blocking.prompt)
        return blocking
    }

    private class BlockingPrompt(
        release: CountDownLatch,
    ) {
        val inFlight = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        val executions = AtomicInteger(0)
        private val response =
            Mockito.mock(PromptResponse::class.java).also { whenever(it.content()).thenReturn("burp-ai answer") }

        val prompt: Prompt =
            Mockito.mock(
                Prompt::class.java,
                Answer { invocation ->
                    if (invocation.method.name != "execute") return@Answer Answers.RETURNS_DEFAULTS.answer(invocation)
                    if (executions.incrementAndGet() == 1) {
                        inFlight.countDown()
                        try {
                            release.await(BLOCK_SECONDS, TimeUnit.SECONDS)
                        } catch (e: InterruptedException) {
                            interrupted.set(true)
                            throw IllegalStateException("execute interrupted", e)
                        }
                    }
                    response
                },
            )
    }

    /** One completion callback, awaited with a failsafe; returns the error it carried. */
    private class Completion {
        private val done = CountDownLatch(1)
        private val error = AtomicReference<Throwable?>()

        fun complete(err: Throwable?) {
            error.set(err)
            done.countDown()
        }

        fun await(seconds: Long = AWAIT_SECONDS): Throwable? {
            assertTrue(done.await(seconds, TimeUnit.SECONDS), "the turn never completed within $seconds s")
            return error.get()
        }
    }

    /** A connection that records its sends and stops and answers nothing. */
    private class RecordingConnection : AgentConnection {
        val sends = AtomicInteger(0)
        val stops = AtomicInteger(0)

        override fun isAlive(): Boolean = stops.get() == 0

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) {
            sends.incrementAndGet()
            onComplete(null)
        }

        override fun stop() {
            stops.incrementAndGet()
        }
    }

    /** A backend whose launch lets the unload begin (after sendChat's entry check) before it returns. */
    private class UnloadingBackend(
        private val connection: AgentConnection,
        private val onLaunch: () -> Unit,
    ) : AiBackend {
        override val id: String = FAKE_ID
        override val displayName: String = "Unloading fake"

        override fun launch(config: BackendLaunchConfig): AgentConnection {
            onLaunch()
            return connection
        }
    }

    private companion object {
        const val CHAT_SESSION = "unload-latch-chat"
        const val FAKE_ID = "unload-race-fake"
        const val AWAIT_SECONDS = 10L
        const val STOP_SECONDS = 5L
        const val BLOCK_SECONDS = 20L
        const val COMPLETION = """{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"""
    }
}
