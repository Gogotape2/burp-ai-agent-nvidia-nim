package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.ChatMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList

class NvidiaNimToolContextTest {
    @Test
    fun chainedToolResultsDoNotRecursivelyCopyEarlierResultsIntoTheCurrentNimPrompt() {
        val harness = ChatPanelTestHarness.create(modelResponse = "unused", settings = TestSettings.baselineSettings("nvidia-nim"))
        val prompts = CopyOnWriteArrayList<String>()
        val histories = CopyOnWriteArrayList<List<ChatMessage>>()
        whenever(harness.api.scope().isInScope(any())).thenReturn(true, false, true, false)
        val call =
            """
            ```json
            {"tool":"scope_check","args":{"url":"https://example.test/"}}
            ```
            """.trimIndent()
        whenever(
            harness.supervisor.sendChat(
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
            histories.add(invocation.getArgument<List<ChatMessage>?>(3).orEmpty().toList())
            @Suppress("UNCHECKED_CAST")
            val onChunk = invocation.arguments[7] as (String) -> Unit

            @Suppress("UNCHECKED_CAST")
            val onComplete = invocation.arguments[8] as (Throwable?) -> Unit
            onChunk(if (prompts.size % 3 == 0) "finished" else call)
            onComplete(null)
            null
        }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(harness, "ROOT_QUESTION_ONE: examine the site map")
            ChatPanelTestHarness.awaitToolSettled(count = 2)
            assertEquals(3, prompts.size)
            assertEquals(1, Regex("Tool result for scope_check:").findAll(prompts[2]).count())
            assertEquals(1, Regex("ROOT_QUESTION_ONE").findAll(prompts[2]).count())
            assertTrue(prompts[2].contains("User request:\nROOT_QUESTION_ONE"))
            assertTrue(prompts[2].contains("in_scope=false"))
            assertTrue(histories[2].any { it.role == "user" && it.content.contains("in_scope=true") })

            ChatPanelTestHarness.sendUserMessage(harness, "ROOT_QUESTION_TWO: examine another endpoint")
            ChatPanelTestHarness.awaitToolSettled(count = 2)
            assertEquals(6, prompts.size)
            assertEquals(1, Regex("Tool result for scope_check:").findAll(prompts[5]).count())
            assertTrue(prompts[5].contains("ROOT_QUESTION_TWO"))
            assertTrue(!prompts[5].contains("ROOT_QUESTION_ONE"))
        } finally {
            harness.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }
}
