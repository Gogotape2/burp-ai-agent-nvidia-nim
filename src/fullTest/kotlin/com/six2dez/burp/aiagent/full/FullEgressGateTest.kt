package com.six2dez.burp.aiagent.full

import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 31 / GATE-04 at the choke point — the full (GitHub) build reaches the same egress gate as the
 * store build, `MontoyaHttpTransport.execute` for HTTP backends and `BurpAiConnection`'s own check for
 * Burp AI, and the only thing that differs is the injected policy, [FullAiAccessPolicy]. It keeps the
 * 1.0.1 rule: Burp's "Use AI" setting gates only `burp-ai`, so every other backend still sends while
 * it is off. Each test drives a real [AgentSupervisor] over a [RecordingMontoya] and counts what really
 * left the extension (`Http.sendRequest` calls and `api.ai().prompt()` calls).
 *
 * Assumption A1 (RESEARCH): on Burp Community `api.ai().isEnabled()` returns false or throws. Both are
 * exercised here (a switched-off setting and a throwing `api.ai()`); the real-edition behaviour is
 * measured in Burp by the D-15 UAT (plan 31-11), so "the full build works on Community" stays an
 * assumption until then.
 */
class FullEgressGateTest {
    private val recording = RecordingMontoya()
    private val audit = mock<AuditLogger>()
    private val promptCalls = AtomicInteger()
    private val supervisor: AgentSupervisor

    init {
        whenever(recording.api.persistence().preferences()).thenReturn(InMemoryPreferences())
        recording.responder = { request ->
            if (request.url.endsWith("/v1/chat/completions")) 200 to COMPLETION else 200 to "{}"
        }
        val response = Mockito.mock(PromptResponse::class.java)
        whenever(response.content()).thenReturn("burp-ai answer")
        val prompt =
            Mockito.mock(
                Prompt::class.java,
                Answer { inv -> if (inv.method.name == "execute") response else Answers.RETURNS_DEFAULTS.answer(inv) },
            )
        whenever(recording.api.ai().prompt()).thenAnswer {
            promptCalls.incrementAndGet()
            prompt
        }
        supervisor = AgentSupervisor(recording.api, BackendRegistry(recording.api), audit, FullAiAccessPolicy())
        supervisor.applySettings(lmStudioSettings())
    }

    @AfterEach
    fun tearDown() {
        supervisor.shutdown()
        recording.close()
    }

    @Test
    fun anLmStudioChatSendReachesTheProviderOnceWhileUseAiIsOff() {
        recording.aiEnabled.set(false)

        val error = chatSend("lmstudio", "full-lmstudio-off")

        assertNull(error, "the full policy does not gate lmstudio on Use AI")
        assertEquals(1, recording.sendCount(), "exactly one provider request")
        assertTrue(
            recording.requests
                .single()
                .url
                .endsWith("/v1/chat/completions"),
        )
    }

    @Test
    fun anLmStudioChatSendReachesTheProviderOnceWhenTheAiApiThrowsAsOnCommunity() {
        whenever(recording.api.ai()).thenThrow(UnsupportedOperationException("no AI API in this Burp edition"))
        assertFalse(supervisor.isAiEnabled(), "a throwing api.ai() reads as Use AI off")

        val error = chatSend("lmstudio", "full-lmstudio-community")

        assertNull(error, "the full build keeps lmstudio working when api.ai() throws")
        assertEquals(1, recording.sendCount(), "exactly one provider request")
    }

    @Test
    fun aBurpAiChatSendIsRefusedWithTheFullPolicyTextWhileUseAiIsOff() {
        recording.aiEnabled.set(false)

        val error = chatSend(BURP_AI, "full-burp-ai-off")

        assertRefusedByFullPolicy(error)
        assertEquals(0, promptCalls.get(), "a refused Burp AI prompt never reaches api.ai().prompt()")
        assertEquals(0, recording.sendCount())
    }

    @Test
    fun aBurpAiChatSendIsRefusedAtTheConnectionWhenUseAiTurnsOffAfterTheEarlyCheck() {
        // Use AI is on for the supervisor's early check; the audit call that follows turns it off, so
        // only the Burp AI connection's own gate is left to refuse (ProviderEgressChokePointTest's trick).
        recording.aiEnabled.set(true)
        whenever(audit.isEnabled()).thenAnswer {
            recording.aiEnabled.set(false)
            false
        }

        val error = chatSend(BURP_AI, "full-burp-ai-flip")

        assertRefusedByFullPolicy(error)
        verify(audit, atLeastOnce()).isEnabled()
        assertEquals(0, promptCalls.get(), "the refused prompt never reaches api.ai().prompt()")
    }

    @Test
    fun aiToolsRequireBurpAiWithOllamaSavedWhileUseAiIsOff() {
        supervisor.applySettings(TestSettings.baselineSettings("ollama"))

        recording.aiEnabled.set(false)
        assertEquals(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI, supervisor.aiToolRefusal())

        recording.aiEnabled.set(true)
        assertNull(supervisor.aiToolRefusal(), "the AI tools are allowed while Use AI is on")
    }

    @Test
    fun theFullPolicyRefusesBurpAiExactlyWhenUseAiIsOff() {
        listOf(true, false).forEach { enabled ->
            val refusal = FullAiAccessPolicy().refusal(BURP_AI, enabled)
            assertEquals(enabled, refusal == null, "full policy for burp-ai with Use AI=$enabled")
        }
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private fun lmStudioSettings(): AgentSettings =
        TestSettings.baselineSettings("lmstudio").copy(
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = "test-model",
        )

    private fun chatSend(
        backendId: String,
        chatSessionId: String,
    ): Throwable? {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        supervisor.sendChat(
            chatSessionId = chatSessionId,
            backendId = backendId,
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
        return error.get()
    }

    private fun assertRefusedByFullPolicy(error: Throwable?) {
        assertTrue(error is AiAccessRefusedException, "expected AiAccessRefusedException, got $error")
        assertEquals(FullAiAccessPolicy().refusal(BURP_AI, false), error?.message)
    }

    private companion object {
        const val BURP_AI = "burp-ai"
        const val AWAIT_SECONDS = 10L
        const val COMPLETION = """{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"""
    }
}
