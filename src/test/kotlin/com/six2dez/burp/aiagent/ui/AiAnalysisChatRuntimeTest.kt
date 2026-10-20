package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.mcp.tools.RecordingAnalysisConnection
import com.six2dez.burp.aiagent.supervisor.ToolAnalysisSession
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList

class AiAnalysisChatRuntimeTest {
    @Test
    fun modelToolCallReceivesTheChatBackendAndReturnsItsResultToTheConversation() {
        val settings =
            TestSettings.baselineSettings("nvidia-nim").let {
                it.copy(mcpSettings = it.mcpSettings.copy(autoApproveToolCalls = true))
            }
        val h = ChatPanelTestHarness.create("unused", settings)
        val connection = RecordingAnalysisConnection()
        whenever(h.supervisor.openToolAnalysisSession("nvidia-nim"))
            .thenReturn(ToolAnalysisSession("nvidia-nim", connection, 1000))
        val prompts = CopyOnWriteArrayList<String>()
        whenever(
            h.supervisor.sendChat(
                any(),
                any(),
                any(),
                anyOrNull(),
                anyOrNull(),
                any(),
                any(),
                any(),
                any(),
                anyOrNull(),
                anyOrNull(),
                anyOrNull(),
                anyOrNull(),
            ),
        ).thenAnswer { invocation ->
            prompts.add(invocation.getArgument(2))
            val response =
                if (prompts.size == 1) {
                    """{"tool":"ai_analyze","args":{"text":"Synthetic offline analysis","jsonMode":true,"maxOutputTokens":2000}}"""
                } else {
                    "Analysis received."
                }
            invocation.getArgument<(String) -> Unit>(7)(response)
            invocation.getArgument<(Throwable?) -> Unit>(8)(null)
            null
        }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Analyze the synthetic fixture")
            ChatPanelTestHarness.awaitToolSettled(count = 1)
            verify(h.supervisor).openToolAnalysisSession("nvidia-nim")
            assertEquals(2, prompts.size)
            assertTrue(prompts.last().contains("Tool result for ai_analyze"))
            assertTrue(prompts.last().contains("{\"ok\":true}"))
            assertFalse(prompts.last().contains("not initialized"))
            assertTrue(connection.jsonMode)
            assertEquals(2000, connection.maxTokens)
            assertFalse(connection.isAlive())
            assertTrue(h.shownErrors.isEmpty())
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }
}
