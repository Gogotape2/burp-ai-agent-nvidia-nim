package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicReference

class AutomaticToolApprovalChatTest {
    @Test
    fun optInRunsHistoryWithoutACardAndContinuesTheModelTurn() {
        val settings = TestSettings.baselineSettings().let { it.copy(mcpSettings = it.mcpSettings.copy(autoApproveToolCalls = true)) }
        val h = ChatPanelTestHarness.create("unused", settings)
        val prompts = captureTurns(h, """{"tool":"proxy_http_history","args":{"count":1}}""")
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "inspect the synthetic history")
            ChatPanelTestHarness.awaitToolSettled(count = 1)
            verify(h.api.proxy(), atLeastOnce()).history()
            assertNull(ChatPanelTestHarness.findApprovalCard(h.panel.root))
            assertEquals(2, prompts.size)
            assertTrue(prompts[1].contains("Tool result for proxy_http_history"))
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun disabledToolRemainsUnavailableWithAutomaticApproval() {
        val settings =
            TestSettings.baselineSettings().let {
                it.copy(mcpSettings = it.mcpSettings.copy(autoApproveToolCalls = true, toolToggles = mapOf("proxy_http_history" to false)))
            }
        val h = ChatPanelTestHarness.create("unused", settings)
        val prompts = captureTurns(h, """{"tool":"proxy_http_history","args":{"count":1}}""")
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "inspect the synthetic history")
            ChatPanelTestHarness.awaitToolSettled(count = 1)
            verify(h.api.proxy(), never()).history()
            assertNull(ChatPanelTestHarness.findApprovalCard(h.panel.root))
            assertTrue(prompts[1].contains("disabled", ignoreCase = true))
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun enabledToolCatalogRefreshesWithinTheSameChat() {
        val current = AtomicReference(TestSettings.baselineSettings())
        val h = ChatPanelTestHarness.create("unused", settingsProvider = { current.get() })
        val prompts = captureTurns(h, "finished")
        try {
            ChatPanelTestHarness.sendUserMessage(h, "first question")
            ChatPanelTestHarness.drainEdt()
            assertFalse(prompts.first().contains("- http1_request:"))
            current.updateAndGet { it.copy(mcpSettings = it.mcpSettings.copy(enabledUnsafeTools = setOf("http1_request"), proxyHistoryMaxItemsPerRequest = 37)) }
            ChatPanelTestHarness.sendUserMessage(h, "second question")
            ChatPanelTestHarness.drainEdt()
            assertTrue(prompts.last().contains("- http1_request:"))
            assertTrue(prompts.last().contains("count limit per call: 37"))
        } finally {
            h.panel.shutdown()
        }
    }

    private fun captureTurns(
        h: ChatPanelTestHarness.Harness,
        firstResponse: String,
    ): CopyOnWriteArrayList<String> {
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
            invocation.getArgument<(String) -> Unit>(7)(if (prompts.size == 1) firstResponse else "finished")
            invocation.getArgument<(Throwable?) -> Unit>(8)(null)
            null
        }
        return prompts
    }
}
