package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.context.ContextCapture
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import javax.swing.JOptionPane
import javax.swing.SwingUtilities

class NvidiaNimAttachedContextTest {
    @Test
    fun attachedContextAndOnceOnlyCatalogAreRetainedInTheFollowingChatTurn() {
        val harness = ChatPanelTestHarness.create(modelResponse = "Context received", settings = TestSettings.baselineSettings("nvidia-nim"))
        val context = """{"items":[{"url":"https://example.test/CONTEXT_MARKER_731"}]}"""
        try {
            SwingUtilities.invokeAndWait {
                Mockito
                    .mockStatic(JOptionPane::class.java) { invocation ->
                        if (invocation.method.name == "showOptionDialog") 0 else invocation.callRealMethod()
                    }.use {
                        harness.panel.startSessionFromContext(ContextCapture(context, "synthetic context"), "Inspect this capture", "Analyze")
                    }
            }
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.sendUserMessage(harness, "Continue using the capture")
            ChatPanelTestHarness.drainEdt()
            val calls = Mockito.mockingDetails(harness.supervisor).invocations.filter { it.method.name == "sendChat" }
            assertEquals(2, calls.size)
            val firstPrompt = calls.first().getArgument<String>(2)
            val secondHistory = calls.last().getArgument<List<ChatMessage>>(3)
            assertTrue(firstPrompt.contains("CONTEXT_MARKER_731"))
            assertEquals(firstPrompt, secondHistory.first { it.role == "user" }.content)
            assertEquals(1, secondHistory.count { it.content.contains("CONTEXT_MARKER_731") })
        } finally {
            harness.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
        }
    }
}
