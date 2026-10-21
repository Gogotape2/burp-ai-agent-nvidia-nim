package com.six2dez.burp.aiagent.ui

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.FunctionCall
import com.six2dez.burp.aiagent.backends.nvidia.NimConversation
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.context.ContextCapture
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CancellationException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

class NvidiaNimNativeChatTest {
    @ParameterizedTest
    @ValueSource(ints = [1, 12, 24])
    fun exhaustedToolChainUsesItsStartingLimitAndNextRequestUsesSavedLimit(limit: Int) {
        val settings = AtomicReference(TestSettings.baselineSettings("nvidia-nim"))
        settings.set(settings.get().copy(nvidiaNimOptions = settings.get().nvidiaNimOptions.copy(maxToolCalls = limit)))
        val h = harness(settingsProvider = settings::get)
        whenever(h.api.scope().isInScope(any())).thenReturn(true)
        var callIndex = 0
        val turns =
            capture(h) { request, emit ->
                // Simulate Save while this chain is active; it must not reset or resize its budget.
                settings.set(settings.get().copy(nvidiaNimOptions = settings.get().nvidiaNimOptions.copy(maxToolCalls = 2)))
                if (request.tools.isNotEmpty()) emit(FunctionCall("scope_${++callIndex}", "scope_check", """{"url":"https://example.test/"}"""))
            }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Inspect the synthetic evidence")
            ChatPanelTestHarness.awaitToolSettled(limit, traceId = turns.first().traceId)
            ChatPanelTestHarness.drainEdt()
            assertEquals(limit + 1, turns.size)
            assertTrue(turns.last().tools.isEmpty())
            assertTrue(
                turns
                    .last()
                    .systemPrompt
                    .orEmpty()
                    .contains("Automatic tool-call limit ($limit) reached"),
            )
            verify(h.api.scope(), org.mockito.kotlin.times(limit)).isInScope(any())
            ChatPanelTestHarness.sendUserMessage(h, "Inspect the next synthetic evidence")
            ChatPanelTestHarness.awaitToolSettled(2, traceId = turns[limit + 1].traceId)
            ChatPanelTestHarness.drainEdt()
            assertEquals(limit + 4, turns.size)
            assertTrue(turns.last().tools.isEmpty())
            assertTrue(
                turns
                    .last()
                    .systemPrompt
                    .orEmpty()
                    .contains("Automatic tool-call limit (2) reached"),
            )
            verify(h.api.scope(), org.mockito.kotlin.times(limit + 2)).isInScope(any())
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun cancelledGenerationLeavesTheNextUserRequestInItsOwnWireTurn() {
        verifyCancellationBoundary(afterTool = false)
    }

    @Test
    fun cancelledToolFollowupLeavesTheNextUserRequestInItsOwnWireTurn() {
        verifyCancellationBoundary(afterTool = true)
    }

    private fun verifyCancellationBoundary(afterTool: Boolean) {
        val h = harness()
        val turns = CopyOnWriteArrayList<AgentChatRequest>()
        val completion = AtomicReference<((Throwable?) -> Unit)?>(null)
        val blocked = mock<AgentConnection>()
        whenever(blocked.stop()).thenAnswer {
            completion.getAndSet(null)?.invoke(CancellationException("Cancelled fixture"))
        }
        whenever(h.api.scope().isInScope(any())).thenReturn(true)
        whenever(h.supervisor.sendAgentChat(any(), any(), any(), any())).thenAnswer { invocation ->
            val request = invocation.getArgument<AgentChatRequest>(0)
            turns.add(request)
            when {
                request.text.contains("NEW_USER_TURN_MARKER") -> {
                    invocation.getArgument<(String) -> Unit>(1)("NEW_USER_TURN_MARKER")
                    invocation.getArgument<(Throwable?) -> Unit>(2)(null)
                    null
                }
                afterTool && request.previousToolResult == null -> {
                    val call = FunctionCall("cancel_scope", "scope_check", """{"url":"https://example.test/"}""")
                    invocation.getArgument<(AgentTurnEvent) -> Unit>(3)(AgentTurnEvent("tool_call", "Native function", call))
                    invocation.getArgument<(String) -> Unit>(1)("""{"tool":"scope_check","args":{"url":"https://example.test/"}}""")
                    invocation.getArgument<(Throwable?) -> Unit>(2)(null)
                    null
                }
                else -> {
                    completion.set(invocation.getArgument(2))
                    blocked
                }
            }
        }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "OLD_REQUEST_MARKER")
            if (afterTool) ChatPanelTestHarness.awaitToolSettled(1, traceId = turns.first().traceId)
            ChatPanelTestHarness.drainEdt()
            assertTrue(completion.get() != null)
            SwingUtilities.invokeAndWait { assertTrue(h.panel.cancelInFlightRequest()) }
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.sendUserMessage(h, "NEW_USER_TURN_MARKER")
            ChatPanelTestHarness.drainEdt()
            val next = turns.last()
            assertNull(next.previousToolResult)
            val wire = NimConversation.prepare(next.history.orEmpty().map { mapOf("role" to it.role, "content" to it.content) }, next.text)
            assertEquals(next.text, wire.messages.last()["content"], "Cancelled context must not merge with the next user request")
            assertEquals("user", wire.messages.last()["role"])
            assertTrue(wire.messages.dropLast(1).any { it["content"].orEmpty().contains("OLD_REQUEST_MARKER") })
            verify(blocked).stop()
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun nativeInvocationTraversesRealApprovalGateAndReturnsItsCorrelatedResult() {
        val h = harness()
        val turns =
            capture(h) { request, emit ->
                if (request.previousToolResult == null) emit(FunctionCall("call_scope", "scope_check", """{"url":"https://example.test/"}"""))
            }
        whenever(h.api.scope().isInScope(any())).thenReturn(true)
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Inspect this synthetic issue")
            ChatPanelTestHarness.awaitToolSettled(1, traceId = turns.first().traceId)
            assertEquals(2, turns.size)
            assertEquals("call_scope", turns[1].previousToolResult?.callId)
            assertTrue(turns[1].previousToolResult!!.content.contains("in_scope=true"))
            assertTrue(turns[0].tools.any { it.name == "scope_check" })
            assertTrue(turns[0].tools.any { it.name == "context_read" })
            assertTrue(turns[0].tools.none { it.name == "http1_request" })
            verify(h.api.scope()).isInScope(any())
            assertNull(ChatPanelTestHarness.findApprovalCard(h.panel.root))
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun largeAttachmentIsReadByNativeContextToolWithoutLoadingUnrelatedProxyHistory() {
        val h = harness()
        val raw = """{"items":[{"name":"Selected issue","detail":"${"body ".repeat(5000)}EXACT_LATE_EVIDENCE"}]}"""
        val turns =
            capture(h) { request, emit ->
                if (request.previousToolResult == null) {
                    val ref = Regex("ctx_[A-Za-z0-9_]+").find(request.text)!!.value
                    val args = jacksonObjectMapper().writeValueAsString(mapOf("id" to ref, "query" to "EXACT_LATE_EVIDENCE", "count" to 100))
                    emit(FunctionCall("call_context", "context_read", args))
                }
            }
        ChatPanelTestHarness.installSettledObserver()
        try {
            SwingUtilities.invokeAndWait {
                Mockito.mockStatic(JOptionPane::class.java) { invocation -> if (invocation.method.name == "showOptionDialog") 0 else invocation.callRealMethod() }.use {
                    h.panel.startSessionFromContext(ContextCapture(raw, "Synthetic issue evidence"), "Inspect selected finding", "Issue Analysis")
                }
            }
            ChatPanelTestHarness.awaitToolSettled(1, traceId = turns.first().traceId)
            assertEquals(2, turns.size)
            assertFalse(turns[0].text.contains("EXACT_LATE_EVIDENCE"))
            assertTrue(turns[1].previousToolResult!!.content.contains("EXACT_LATE_EVIDENCE"))
            assertEquals("call_context", turns[1].previousToolResult?.callId)
            verify(h.api.proxy(), never()).history()
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun disabledContextReadKeepsTheAttachmentInlineAndOutOfNativeDefinitions() {
        val h = harness(contextRead = false)
        val turns = capture(h) { _, _ -> }
        val raw = """{"items":[{"detail":"${"evidence ".repeat(2000)}INLINE_MARKER"}]}"""
        try {
            SwingUtilities.invokeAndWait {
                Mockito.mockStatic(JOptionPane::class.java) { invocation -> if (invocation.method.name == "showOptionDialog") 0 else invocation.callRealMethod() }.use {
                    h.panel.startSessionFromContext(ContextCapture(raw, "Synthetic capture"), "Inspect", "Analyze")
                }
            }
            ChatPanelTestHarness.drainEdt()
            assertEquals(1, turns.size)
            assertTrue(turns[0].text.contains("INLINE_MARKER"))
            assertTrue(turns[0].tools.none { it.name == "context_read" })
            assertFalse(turns[0].text.contains("contextRef"))
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
        }
    }

    private fun harness(
        contextRead: Boolean = true,
        settingsProvider: (() -> AgentSettings)? = null,
    ): ChatPanelTestHarness.Harness {
        val settings = TestSettings.baselineSettings("nvidia-nim")
        val configured = { (settingsProvider?.invoke() ?: settings).let { it.copy(mcpSettings = it.mcpSettings.copy(autoApproveToolCalls = true, toolToggles = it.mcpSettings.toolToggles + ("context_read" to contextRead))) } }
        val h = ChatPanelTestHarness.create("unused", settingsProvider = configured)
        val backend = mock<AiBackend>()
        whenever(backend.supportsSystemRole).thenReturn(true)
        whenever(h.supervisor.getBackend("nvidia-nim")).thenReturn(backend)
        return h
    }

    private fun capture(
        h: ChatPanelTestHarness.Harness,
        respond: (AgentChatRequest, (FunctionCall) -> Unit) -> Unit,
    ): CopyOnWriteArrayList<AgentChatRequest> {
        val turns = CopyOnWriteArrayList<AgentChatRequest>()
        whenever(h.supervisor.sendAgentChat(any(), any(), any(), any())).thenAnswer { invocation ->
            val request = invocation.getArgument<AgentChatRequest>(0)
            turns.add(request)
            var emitted = false
            respond(request) { call ->
                emitted = true
                invocation.getArgument<(AgentTurnEvent) -> Unit>(3)(AgentTurnEvent("tool_call", "Native function", call))
                invocation.getArgument<(String) -> Unit>(1)(jacksonObjectMapper().writeValueAsString(mapOf("tool" to call.name, "args" to jacksonObjectMapper().readTree(call.argumentsJson))))
            }
            if (!emitted) invocation.getArgument<(String) -> Unit>(1)("Completed using observed evidence.")
            invocation.getArgument<(Throwable?) -> Unit>(2)(null)
            null
        }
        return turns
    }
}
