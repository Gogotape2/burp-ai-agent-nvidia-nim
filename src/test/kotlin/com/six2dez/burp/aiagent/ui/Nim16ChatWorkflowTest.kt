package com.six2dez.burp.aiagent.ui

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.FunctionCall
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.SwingUtilities

class Nim16ChatWorkflowTest {
    @Test
    fun cancellingAfterSwitchingSessionsStopsTheOriginalToolProgressWithoutResumingIt() {
        val h = harness()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val payload = "CANCELLED_TOOL_RESULT_MARKER"
        whenever(
            h.api
                .utilities()
                .urlUtils()
                .encode(payload),
        ).thenAnswer {
            entered.countDown()
            check(release.await(10, TimeUnit.SECONDS))
            payload
        }
        val turns = capture(h) { FunctionCall("blocked_encoding", "url_encode", """{"content":"$payload"}""") }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Преобразуй строку инструментом")
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(toolProgressVisible(h), "The tool must actually be waiting before cancellation")
            SwingUtilities.invokeAndWait { h.panel.createNewSession() }
            SwingUtilities.invokeAndWait { assertTrue(h.panel.cancelInFlightRequest()) }
            assertFalse(toolProgressVisible(h), "The original session's tool clock must stop immediately")
            release.countDown()
            ChatPanelTestHarness.awaitToolSettled(1, traceId = turns.first().traceId)
            ChatPanelTestHarness.drainEdt()
            assertFalse(toolProgressVisible(h), "A late tool result cannot restart its clock")
            assertFalse(visibleText(h).contains(payload))
            assertEquals(1, turns.size, "Cancellation must not submit a model followup")
        } finally {
            release.countDown()
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    private fun toolProgressVisible(h: ChatPanelTestHarness.Harness): Boolean = components(h.panel.root).filterIsInstance<JLabel>().any { it.isVisible && it.text.orEmpty().contains("Выполняется инструмент") }

    @Test
    fun rawNativeArgumentsAndResultsStayInTheWireButNotTheVisibleChatOrItsRestoration() {
        val h = harness()
        val payload = "RAW_TOOL_PAYLOAD_MARKER".repeat(100)
        whenever(
            h.api
                .utilities()
                .urlUtils()
                .encode(payload),
        ).thenReturn(payload)
        val turns =
            capture(h) { request ->
                if (request.previousToolResult == null) FunctionCall("encoding", "url_encode", jacksonObjectMapper().writeValueAsString(mapOf("content" to payload))) else null
            }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Выполни преобразование строки инструментом")
            ChatPanelTestHarness.awaitToolSettled(1, traceId = turns.first().traceId)
            ChatPanelTestHarness.drainEdt()
            assertTrue(
                turns
                    .first()
                    .systemPrompt
                    .orEmpty()
                    .contains("reply to the user in Russian"),
            )
            assertTrue(turns[1].previousToolResult!!.content.contains(payload), "The model followup must retain the complete synthetic result")
            assertFalse(visibleText(h).contains("RAW_TOOL_PAYLOAD_MARKER"))
            assertTrue(visibleText(h).contains("Данные скрыты"), "Compact status must be visible: ${visibleText(h)}")
            val saved = mutableMapOf<String, String>()
            val prefs = h.api.persistence().extensionData()
            whenever(prefs.getString(any())).thenAnswer { saved[it.getArgument(0)] }
            doAnswer {
                saved[it.getArgument(0)] = it.getArgument(1)
                null
            }.whenever(prefs).setString(any(), any())
            SwingUtilities.invokeAndWait { h.panel.saveSessions() }
            assertTrue(saved.values.any { it.contains(payload) })
            val restored = restoreIntoFreshPanel(saved)
            try {
                assertFalse(visibleText(restored).contains("RAW_TOOL_PAYLOAD_MARKER"))
                assertTrue(visibleText(restored).contains("Данные скрыты"), "A fresh panel must render the restored compact call")
            } finally {
                restored.panel.shutdown()
                ChatPanelTestHarness.drainEdt()
            }
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    private fun restoreIntoFreshPanel(saved: Map<String, String>): ChatPanelTestHarness.Harness {
        val restored = harness()
        whenever(
            restored.api
                .persistence()
                .extensionData()
                .getString(any()),
        ).thenAnswer { saved[it.getArgument(0)] }
        SwingUtilities.invokeAndWait {
            restored.panel.clearInMemorySessionState()
            restored.panel.restoreSessions()
        }
        ChatPanelTestHarness.drainEdt()
        return restored
    }

    @Test
    fun unexecutedPracticalRequestOffersAnExplicitRetryWithoutStartingOneAutomatically() {
        val h = harness(active = true)
        val turns = capture(h) { null }
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Теперь проверь на практике реальна ли уязвимость")
            ChatPanelTestHarness.drainEdt()
            val run = components(h.panel.root).filterIsInstance<JButton>().single { it.text == "Выполнить проверку" }
            assertTrue(run.isEnabled)
            assertEquals(1, turns.size)
            SwingUtilities.invokeAndWait { run.doClick() }
            ChatPanelTestHarness.drainEdt()
            assertEquals(2, turns.size)
            assertTrue(turns.last().text.contains("Исходная задача"))
            assertTrue(turns.last().tools.any { it.name == "http1_request" })
            assertFalse(run.isEnabled)
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
        }
    }

    @Test
    fun unavailableToolsDisableTheExecutionButtonAndStaleCardsCannotSubmitNewTasks() {
        val h = harness()
        val turns = capture(h) { null }
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Начни проверять таргет")
            ChatPanelTestHarness.drainEdt()
            val run = components(h.panel.root).filterIsInstance<JButton>().single { it.text == "Выполнить проверку" }
            assertFalse(run.isEnabled)
            assertNotNull(run.toolTipText)
            assertEquals(1, turns.size)
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
        }
        val enabled = harness(active = true)
        val enabledTurns = capture(enabled) { null }
        try {
            ChatPanelTestHarness.sendUserMessage(enabled, "Начни проверять таргет")
            ChatPanelTestHarness.drainEdt()
            val old = components(enabled.panel.root).filterIsInstance<JButton>().single { it.text == "Выполнить проверку" }
            ChatPanelTestHarness.sendUserMessage(enabled, "Объясни предыдущее наблюдение")
            ChatPanelTestHarness.drainEdt()
            SwingUtilities.invokeAndWait { old.doClick() }
            ChatPanelTestHarness.drainEdt()
            assertEquals(2, enabledTurns.size)
        } finally {
            enabled.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
        }
    }

    private fun harness(active: Boolean = false): ChatPanelTestHarness.Harness {
        val settings = TestSettings.baselineSettings("nvidia-nim")
        val configured = settings.copy(mcpSettings = settings.mcpSettings.copy(autoApproveToolCalls = true, unsafeEnabled = active, toolToggles = settings.mcpSettings.toolToggles + ("http1_request" to active)))
        val h = ChatPanelTestHarness.create("unused", configured)
        val backend = mock<AiBackend>()
        whenever(backend.supportsSystemRole).thenReturn(true)
        whenever(h.supervisor.getBackend("nvidia-nim")).thenReturn(backend)
        return h
    }

    private fun capture(
        h: ChatPanelTestHarness.Harness,
        respond: (AgentChatRequest) -> FunctionCall?,
    ): CopyOnWriteArrayList<AgentChatRequest> {
        val turns = CopyOnWriteArrayList<AgentChatRequest>()
        whenever(h.supervisor.sendAgentChat(any(), any(), any(), any())).thenAnswer { invocation ->
            val request = invocation.getArgument<AgentChatRequest>(0)
            turns.add(request)
            val call = respond(request)
            if (call != null) {
                invocation.getArgument<(AgentTurnEvent) -> Unit>(3)(AgentTurnEvent("tool_call", "Native function", call))
                invocation.getArgument<(String) -> Unit>(1)(jacksonObjectMapper().writeValueAsString(mapOf("tool" to call.name, "args" to jacksonObjectMapper().readTree(call.argumentsJson))))
            } else {
                invocation.getArgument<(String) -> Unit>(1)("Наблюдение обработано.")
            }
            invocation.getArgument<(Throwable?) -> Unit>(2)(null)
            null
        }
        return turns
    }

    private fun components(component: Component): Sequence<Component> =
        sequence {
            yield(component)
            if (component is Container) component.components.forEach { yieldAll(components(it)) }
        }

    private fun visibleText(h: ChatPanelTestHarness.Harness): String = components(h.panel.root).filterIsInstance<JEditorPane>().joinToString("\n") { it.document.getText(0, it.document.length) }
}
