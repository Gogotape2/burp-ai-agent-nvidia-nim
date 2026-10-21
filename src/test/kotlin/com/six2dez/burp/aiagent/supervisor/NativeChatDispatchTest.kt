package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.FunctionResult
import com.six2dez.burp.aiagent.backends.FunctionTool
import com.six2dez.burp.aiagent.backends.ToolCallingConnection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.Executors

class NativeChatDispatchTest {
    @Test
    fun supervisorForwardsStructuredOptionsProgressAndCallbacksAndReusesTheConnection() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = mock<BackendRegistry>()
        val backend = mock<AiBackend>()
        val native = NativeRecorder()
        whenever(registry.listAllBackendIds()).thenReturn(emptyList())
        whenever(registry.get("nvidia-nim")).thenReturn(backend)
        whenever(backend.launch(any())).thenReturn(native)
        val pool = Executors.newSingleThreadExecutor()
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), pool)
        val events = mutableListOf<AgentTurnEvent>()
        val chunks = mutableListOf<String>()
        var completed = 0
        try {
            supervisor.applySettings(TestSettings.baselineSettings("nvidia-nim"))
            val first = AgentChatRequest("chat-native-dispatch", "nvidia-nim", "root", traceId = "trace-one", tools = listOf(FunctionTool("status", "status", "{}")), systemPrompt = "instruction", maxOutputTokens = 333)
            assertSame(
                native,
                supervisor.sendAgentChat(first, { chunks.add(it) }, {
                    assertNull(it)
                    completed++
                }, { events.add(it) }),
            )
            val followup = first.copy(previousToolResult = FunctionResult("call-1", "result"), text = "continue")
            supervisor.sendAgentChat(followup, { chunks.add(it) }, {
                assertNull(it)
                completed++
            }, { events.add(it) })
            assertEquals(listOf(first, followup), native.requests)
            assertEquals(2, completed)
            assertEquals(listOf("answer", "answer"), chunks)
            assertTrue(events.all { it.stage == "provider" })
            verify(backend, times(1)).launch(any())
        } finally {
            supervisor.shutdown()
            pool.shutdownNow()
        }
    }

    private class NativeRecorder :
        AgentConnection,
        ToolCallingConnection {
        val requests = mutableListOf<AgentChatRequest>()
        private var alive = true

        override fun isAlive(): Boolean = alive

        override fun stop() {
            alive = false
        }

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) {
            error("Legacy send must not discard native options")
        }

        override fun sendAgentTurn(
            request: AgentChatRequest,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            onEvent: (AgentTurnEvent) -> Unit,
        ) {
            requests.add(request)
            onEvent(AgentTurnEvent("provider", "waiting"))
            onChunk("answer")
            onComplete(null)
        }
    }
}
