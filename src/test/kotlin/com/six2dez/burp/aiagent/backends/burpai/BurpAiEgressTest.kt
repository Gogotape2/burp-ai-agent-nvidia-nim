package com.six2dez.burp.aiagent.backends.burpai

import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 31 / GATE-01, RESEARCH Pattern 2 — Burp AI sends no HTTP request, so `BurpAiConnection` asks
 * the same egress gate itself: the transport core bound to `burp-ai` must allow the request before
 * `api.ai().prompt().execute` runs. Each test counts the `api.ai().prompt()` calls, which is what
 * would really reach Burp's bundled AI.
 *
 * Equivalence: for the id `burp-ai` the store policy refuses exactly when `api.ai().isEnabled()` is
 * false, so "refused at the gate" and "Use AI is off" mean the same thing for Burp AI. The full
 * build's policy is pinned the same way in FullEgressGateTest.
 */
class BurpAiEgressTest {
    private val recording = RecordingMontoya()
    private val promptCalls = AtomicInteger()
    private val executeCalls = AtomicInteger()
    private val supervisors = CopyOnWriteArrayList<AgentSupervisor>()

    init {
        val response = Mockito.mock(PromptResponse::class.java)
        whenever(response.content()).thenReturn(ANSWER)
        val prompt =
            Mockito.mock(
                Prompt::class.java,
                Answer { inv ->
                    if (inv.method.name == "execute") {
                        executeCalls.incrementAndGet()
                        response
                    } else {
                        Answers.RETURNS_DEFAULTS.answer(inv)
                    }
                },
            )
        whenever(recording.api.ai().prompt()).thenAnswer {
            promptCalls.incrementAndGet()
            prompt
        }
    }

    @AfterEach
    fun tearDown() {
        supervisors.forEach { it.shutdown() }
        recording.close()
    }

    @Test
    fun aPromptIsRefusedByTheStoreGateWhileUseAiIsOff() {
        recording.aiEnabled.set(false)

        val result = send(storeGatedTransport().forBackend(BURP_AI))

        assertTrue(result.error is AiAccessRefusedException, "expected AiAccessRefusedException, got ${result.error}")
        assertEquals(StoreAiAccessPolicy().refusal(BURP_AI, false), result.error?.message)
        assertEquals(0, promptCalls.get(), "a refused prompt never reaches api.ai().prompt()")
        assertEquals(0, executeCalls.get())
        assertTrue(result.chunks.isEmpty())
    }

    @Test
    fun aPromptIsExecutedOnceWhileUseAiIsOn() {
        recording.aiEnabled.set(true)

        val result = send(storeGatedTransport().forBackend(BURP_AI))

        assertNull(result.error, "the allowed prompt must complete without an error")
        assertEquals(1, executeCalls.get(), "prompt().execute runs exactly once")
        assertEquals(listOf(ANSWER), result.chunks, "the Burp AI answer reaches onChunk")
    }

    @Test
    fun aConnectionWithoutATransportRefusesEveryPrompt() {
        recording.aiEnabled.set(true)

        val result = send(transport = null)

        assertTrue(result.error is AiAccessRefusedException, "expected AiAccessRefusedException, got ${result.error}")
        assertEquals(MontoyaHttpTransport.UNBOUND_REFUSAL, result.error?.message)
        assertEquals(0, promptCalls.get(), "fail closed: no prompt without a transport")
    }

    @Test
    fun theStorePolicyRefusesBurpAiExactlyWhenUseAiIsOff() {
        listOf(true, false).forEach { enabled ->
            val refusal = StoreAiAccessPolicy().refusal(BURP_AI, enabled)
            assertEquals(enabled, refusal == null, "store policy for burp-ai with Use AI=$enabled")
        }
    }

    @Test
    fun aSupervisorChatSendIsRefusedAtTheConnectionWhenUseAiTurnsOffAfterTheEarlyCheck() {
        val audit = mock<AuditLogger>()
        whenever(recording.api.persistence().preferences()).thenReturn(InMemoryPreferences())
        val supervisor = AgentSupervisor(recording.api, BackendRegistry(recording.api), audit, StoreAiAccessPolicy())
        supervisors += supervisor
        supervisor.applySettings(TestSettings.baselineSettings(BURP_AI))
        // The early check reads Use AI ON; the audit call that follows it turns Use AI OFF, so only
        // the connection's own gate is left to refuse (ProviderEgressChokePointTest's ordering trick).
        recording.aiEnabled.set(true)
        whenever(audit.isEnabled()).thenAnswer {
            recording.aiEnabled.set(false)
            false
        }

        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        val connection =
            supervisor.sendChat(
                chatSessionId = "burp-ai-flip",
                backendId = BURP_AI,
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
        assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the chat send must complete")

        assertNotNull(connection, "the early check passed, so a Burp AI connection was launched")
        assertTrue(error.get() is AiAccessRefusedException, "expected AiAccessRefusedException, got ${error.get()}")
        assertEquals(StoreAiAccessPolicy().refusal(BURP_AI, false), error.get()?.message)
        verify(audit, atLeastOnce()).isEnabled()
        assertEquals(0, promptCalls.get(), "the refused prompt never reaches api.ai().prompt()")
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private class SendResult(
        val error: Throwable?,
        val chunks: List<String>,
    )

    // The production gate shape: the store policy applied to a live read of Use AI.
    private fun storeGatedTransport(): MontoyaHttpTransport =
        MontoyaHttpTransport(recording.api) { id -> StoreAiAccessPolicy().refusal(id, recording.aiEnabled.get()) }

    private fun send(transport: MontoyaHttpTransport?): SendResult {
        val connection =
            BurpAiBackend(recording.api).launch(
                BackendLaunchConfig(
                    backendId = BURP_AI,
                    displayName = "Burp AI (built-in)",
                    sessionId = "burp-ai-test",
                    transport = transport,
                ),
            )
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        val chunks = CopyOnWriteArrayList<String>()
        try {
            connection.send(
                text = "hello",
                history = null,
                onChunk = { chunks += it },
                onComplete = { err ->
                    error.set(err)
                    done.countDown()
                },
            )
            assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the Burp AI send must complete")
        } finally {
            connection.stop()
        }
        return SendResult(error.get(), chunks.toList())
    }

    private companion object {
        const val BURP_AI = "burp-ai"
        const val ANSWER = "burp-ai answer"
        const val AWAIT_SECONDS = 10L
    }
}
