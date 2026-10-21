package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.ChatMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList

class NvidiaNimIssueToolFlowTest {
    @Test
    fun issueReportDoesNotStartAnotherModelTurnOrInvokeBurp() {
        val report =
            """
            Analysis of the selected issue:
            ```json
            {"name":"Authentication Bypass: Login Accepts Arbitrary Credentials","severity":"High"}
            ```
            The provided evidence does not establish the impact.
            """.trimIndent()
        val h = harness()
        val turns = captureTurns(h) { report }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Analyze the selected issue")
            ChatPanelTestHarness.drainEdt()
            assertEquals(1, turns.size)
            assertFalse(ChatPanelTestHarness.dispatchedLabels().contains(turns.first().traceId))
            verify(h.api.proxy(), never()).history()
            assertNull(ChatPanelTestHarness.findApprovalCard(h.panel.root))
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun enabledCatalogStaysInSystemRoleAcrossActualToolStepsAndNewQuestions() {
        val h = harness()
        val call = """{"tool":"scope_check","args":{"url":"https://example.test/"}}"""
        val turns = captureTurns(h) { if (it == 1) call else "The captured evidence is insufficient." }
        whenever(h.api.scope().isInScope(any())).thenReturn(true)
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Analyze ISSUE_MARKER_917 using evidence")
            ChatPanelTestHarness.awaitToolSettled(count = 1, traceId = turns.first().traceId)
            ChatPanelTestHarness.sendUserMessage(h, "Recheck this issue")
            ChatPanelTestHarness.drainEdt()
            assertEquals(3, turns.size)
            for (turn in turns) {
                assertTrue(turn.system.orEmpty().contains("- scope_check:"))
                assertTrue(turn.system.orEmpty().contains("first inspect relevant evidence"))
                assertFalse(turn.prompt.contains("- scope_check:"))
                assertTrue(turn.history.none { it.content.contains("- scope_check:") })
            }
            assertTrue(turns[1].prompt.contains("in_scope=true"))
            assertTrue(turns[1].prompt.contains("ISSUE_MARKER_917"))
            verify(h.api.scope()).isInScope(any())
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    @Test
    fun unknownExplicitToolGetsOneFinalCompletionWithoutAnAutomaticRetryLoop() {
        val h = harness()
        val turns = captureTurns(h) { """{"tool":"invented_issue_tool","args":{}}""" }
        ChatPanelTestHarness.installSettledObserver()
        try {
            ChatPanelTestHarness.sendUserMessage(h, "Analyze the selected issue")
            ChatPanelTestHarness.awaitToolSettled(count = 1, traceId = turns.first().traceId)
            ChatPanelTestHarness.drainEdt()
            assertEquals(2, turns.size)
            assertTrue(turns[1].prompt.contains("Unknown tool: invented_issue_tool"))
            assertTrue(turns[1].system.orEmpty().contains("Tool calls are disabled for this completion"))
            assertFalse(turns[1].system.orEmpty().contains("- scope_check:"))
            assertFalse(turns[1].prompt.contains("- scope_check:"))
            verify(h.api.proxy(), never()).history()
        } finally {
            h.panel.shutdown()
            ChatPanelTestHarness.drainEdt()
            ChatPanelTestHarness.releaseSettledObserver()
        }
    }

    private fun harness(): ChatPanelTestHarness.Harness {
        val settings = TestSettings.baselineSettings("nvidia-nim")
        val h = ChatPanelTestHarness.create("unused", settings.copy(mcpSettings = settings.mcpSettings.copy(autoApproveToolCalls = true)))
        val backend = mock<AiBackend>()
        whenever(backend.supportsSystemRole).thenReturn(true)
        whenever(h.supervisor.getBackend("nvidia-nim")).thenReturn(backend)
        return h
    }

    private data class Turn(
        val prompt: String,
        val system: String?,
        val history: List<ChatMessage>,
        val traceId: String,
    )

    private fun captureTurns(
        h: ChatPanelTestHarness.Harness,
        response: (Int) -> String,
    ): CopyOnWriteArrayList<Turn> {
        val turns = CopyOnWriteArrayList<Turn>()
        whenever(
            h.supervisor.sendChat(any(), any(), any(), anyOrNull(), anyOrNull(), any(), any(), any(), any(), anyOrNull(), anyOrNull(), anyOrNull(), anyOrNull()),
        ).thenAnswer { invocation ->
            turns.add(Turn(invocation.getArgument(2), invocation.getArgument(10), invocation.getArgument<List<ChatMessage>?>(3).orEmpty().toList(), invocation.getArgument(9)))
            invocation.getArgument<(String) -> Unit>(7)(response(turns.size))
            invocation.getArgument<(Throwable?) -> Unit>(8)(null)
            null
        }
        return turns
    }
}
