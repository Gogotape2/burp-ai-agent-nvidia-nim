package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 31 / GATE-01, SC1, D-04, D-12 — every HTTP AI-provider path is refused at the one egress
 * choke point, `MontoyaHttpTransport.execute`, when Burp's "Use AI" is off in the store build: a chat
 * send, the next tool-loop turn, `supervisor.send` (the passive scanner, the active scanner's
 * AdaptivePayloadEngine and MCP `ai_analyze` all use it) and `registry.healthCheck` (the status pill
 * and Test connection, which only passes unsaved settings). Each test counts what really reached
 * Burp's HTTP stack ([RecordingMontoya.sendCount]).
 *
 * The ordering trick (RESEARCH "Proving the choke point itself"): `AgentSupervisor.sendChat` and
 * `send` run their early `aiAccessRefusal` check FIRST, then call `audit.isEnabled()`, and only then
 * hand the prompt to the connection. "Use AI" starts ON, and the mocked `AuditLogger.isEnabled()`
 * turns it OFF when called. The early check therefore passes, and the only thing left that can
 * refuse is the transport's own per-request gate. This depends on that statement order: if
 * `audit.isEnabled()` ever moved above the early check, the early check would refuse instead, and
 * the tests assert that `audit.isEnabled()` was invoked so a reorder fails them rather than letting
 * them pass for the wrong reason. The registry health paths have no early check, so they need no trick.
 */
class ProviderEgressChokePointTest {
    private val recording = RecordingMontoya()
    private val prefs = InMemoryPreferences()
    private val audit = mock<AuditLogger>()
    private val registry: BackendRegistry
    private val supervisor: AgentSupervisor

    init {
        whenever(recording.api.persistence().preferences()).thenReturn(prefs)
        recording.responder = { request ->
            if (request.url.endsWith("/v1/chat/completions")) 200 to COMPLETION else 200 to "{}"
        }
        registry = BackendRegistry(recording.api)
        supervisor = AgentSupervisor(recording.api, registry, audit, StoreAiAccessPolicy())
        supervisor.applySettings(settings())
    }

    @AfterEach
    fun tearDown() {
        supervisor.shutdown()
        recording.close()
    }

    @Test
    fun chatSendWithUseAiOnReachesTheProviderOnceWithUpstreamTls() {
        recording.aiEnabled.set(true)

        val error = chatSend("s-on")

        assertNull(error, "the allowed chat send must complete without an error")
        assertEquals(1, recording.sendCount(), "exactly one provider request")
        assertTrue(
            recording.requests
                .single()
                .url
                .endsWith("/v1/chat/completions"),
        )
        verify(recording.options, times(1)).withUpstreamTLSVerification()
    }

    @Test
    fun chatSendIsRefusedAtTheTransportWhenUseAiTurnsOffAfterTheEarlyCheck() {
        recording.aiEnabled.set(true)
        turnUseAiOffWhenAuditIsAsked()

        val error = chatSend("s-flip")

        assertRefusedByStorePolicy(error)
        verify(audit, atLeastOnce()).isEnabled()
        assertEquals(0, recording.sendCount(), "a refused request never reaches Http.sendRequest")
    }

    @Test
    fun toolLoopTurnIsRefusedOnTheReusedConnection() {
        recording.aiEnabled.set(true)
        val first = AtomicReference<AgentConnection?>()
        assertNull(chatSend("s1", first), "the first turn is answered")
        assertEquals(1, recording.sendCount())

        turnUseAiOffWhenAuditIsAsked()
        val second = AtomicReference<AgentConnection?>()
        val error = chatSend("s1", second)

        assertSame(first.get(), second.get(), "the next turn reuses the chat connection")
        assertRefusedByStorePolicy(error)
        verify(audit, atLeastOnce()).isEnabled()
        assertEquals(1, recording.sendCount(), "the refused turn sends nothing; the answered one stays answered")
    }

    @Test
    fun supervisorSendIsRefusedAtTheTransportWhenUseAiTurnsOffAfterTheEarlyCheck() {
        recording.aiEnabled.set(true)
        assertTrue(supervisor.startOrAttach("lmstudio"), "the backend starts while Use AI is on")
        turnUseAiOffWhenAuditIsAsked()

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        supervisor.send(
            text = "analyze",
            contextJson = null,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            onChunk = {},
            onComplete = { err ->
                error.set(err)
                done.countDown()
            },
        )
        assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "supervisor.send must complete")

        assertRefusedByStorePolicy(error.get())
        verify(audit, atLeastOnce()).isEnabled()
        assertEquals(0, recording.sendCount())
    }

    @Test
    fun healthCheckOfEveryHttpBackendIsTheStoreRefusalWhileUseAiIsOff() {
        recording.aiEnabled.set(false)

        HTTP_BACKEND_IDS.forEach { id ->
            val result = registry.healthCheck(id, settings())
            assertEquals(
                HealthCheckResult.Unavailable(StoreAiAccessPolicy().refusal(id, false)!!),
                result,
                "$id health (status pill and Test connection) must carry the store refusal",
            )
        }
        assertEquals(0, recording.sendCount(), "no health request leaves Burp while Use AI is off")
    }

    @Test
    fun healthCheckWithUseAiOnReachesTheProviderOnce() {
        recording.aiEnabled.set(true)

        assertEquals(HealthCheckResult.Healthy, registry.healthCheck("lmstudio", settings()))
        assertEquals(1, recording.sendCount(), "the allowed health check really reaches Http.sendRequest")
        assertTrue(
            recording.requests
                .single()
                .url
                .endsWith("/v1/models"),
        )
    }

    // --- Helpers ---------------------------------------------------------------------------------

    // Every backend gets a URL, a model and an API key, so each one's own field validation passes and
    // its health check really reaches its transport.
    private fun settings(): AgentSettings =
        TestSettings.baselineSettings("lmstudio").copy(
            ollamaUrl = "http://127.0.0.1:11434",
            ollamaModel = "test-model",
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = "test-model",
            openAiCompatibleUrl = "http://127.0.0.1:8000/v1",
            openAiCompatibleModel = "test-model",
            openAiCompatibleApiKey = "test-key",
            nvidiaNimUrl = "https://integrate.api.nvidia.com",
            nvidiaNimModel = "test-model",
            nvidiaNimApiKey = "test-key",
            perplexityUrl = "https://api.perplexity.ai",
            perplexityModel = "test-model",
            perplexityApiKey = "test-key",
            anthropicModel = "test-model",
            anthropicApiKey = "test-key",
        )

    private fun turnUseAiOffWhenAuditIsAsked() {
        whenever(audit.isEnabled()).thenAnswer {
            recording.aiEnabled.set(false)
            false
        }
    }

    private fun chatSend(
        chatSessionId: String,
        connectionOut: AtomicReference<AgentConnection?> = AtomicReference(),
    ): Throwable? {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        val connection =
            supervisor.sendChat(
                chatSessionId = chatSessionId,
                backendId = "lmstudio",
                text = "hello",
                contextJson = null,
                privacyMode = PrivacyMode.OFF,
                determinismMode = false,
                onChunk = {},
                onComplete = { err ->
                    error.set(err)
                    done.countDown()
                },
            )
        connectionOut.set(connection)
        assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the chat send must complete")
        return error.get()
    }

    private fun assertRefusedByStorePolicy(error: Throwable?) {
        assertTrue(error is AiAccessRefusedException, "expected AiAccessRefusedException, got $error")
        assertEquals(StoreAiAccessPolicy().refusal("lmstudio", false), error?.message)
    }

    private companion object {
        const val AWAIT_SECONDS = 10L
        val HTTP_BACKEND_IDS = listOf("ollama", "lmstudio", "openai-compatible", "nvidia-nim", "perplexity", "anthropic")
        const val COMPLETION = """{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"""
    }
}
