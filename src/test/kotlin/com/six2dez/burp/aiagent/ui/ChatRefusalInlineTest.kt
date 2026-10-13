package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import javax.swing.JEditorPane
import javax.swing.SwingUtilities

/**
 * Phase 31 / D-01 (b) and D-09, through a real [ChatPanel] driven by its real Send button.
 *
 * - A send the injected policy refuses is explained INLINE in the transcript with the policy's own
 *   text, opens no modal error, sends nothing, and still reports the turn so the pill can show
 *   "AI disabled in Burp".
 * - Every settled turn reports its backend id and its outcome (null on success, the error otherwise),
 *   which is what lets MainTab refresh the pill from the turn that already happened, with no extra
 *   request.
 */
class ChatRefusalInlineTest {
    @Test
    fun aRefusedSendIsExplainedInlineWithThePolicyTextAndNoDialog() {
        val h = ChatPanelTestHarness.create(modelResponse = "unused", settings = TestSettings.baselineSettings(BACKEND_ID))
        whenever(h.supervisor.aiAccessRefusal(any())).thenReturn(REFUSAL)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        ChatPanelTestHarness.drainEdt()

        assertEquals(emptyList<String>(), h.shownErrors.toList(), "A refused send must not open the modal error sink.")
        assertEquals(emptyList<String>(), h.sentTraceIds.toList(), "A refused send must not reach sendChat.")
        assertEquals(
            1,
            transcriptTexts(h).count { it == REFUSAL },
            "The transcript must hold exactly one message whose text is the policy's refusal; texts: ${transcriptTexts(h)}",
        )
        val outcome = h.turnOutcomes.singleOrNull()
        assertTrue(outcome != null, "A refused send must report exactly one settled turn; got ${h.turnOutcomes.toList()}")
        assertEquals(BACKEND_ID, outcome!!.first)
        val error = outcome.second
        assertTrue(error is AiAccessRefusedException, "The refused turn must carry AiAccessRefusedException; got $error")
        assertEquals(REFUSAL, error!!.message)
    }

    @Test
    fun aDeliveredTurnReportsItsBackendWithNoError() {
        val h = ChatPanelTestHarness.create(modelResponse = "ok", settings = TestSettings.baselineSettings(BACKEND_ID))

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        ChatPanelTestHarness.drainEdt()

        assertEquals(1, h.turnOutcomes.size, "One delivered turn must be reported once; got ${h.turnOutcomes.toList()}")
        assertEquals(BACKEND_ID, h.turnOutcomes.single().first)
        assertNull(h.turnOutcomes.single().second)
        assertEquals(emptyList<String>(), h.shownErrors.toList())
    }

    @Test
    fun aFailedTurnDeliversItsOwnError() {
        val boom = IllegalStateException("boom")
        val h =
            ChatPanelTestHarness.create(
                modelResponse = "",
                settings = TestSettings.baselineSettings(BACKEND_ID),
                completionError = boom,
            )

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        ChatPanelTestHarness.drainEdt()

        assertEquals(1, h.turnOutcomes.size, "One failed turn must be reported once; got ${h.turnOutcomes.toList()}")
        assertEquals(BACKEND_ID, h.turnOutcomes.single().first)
        assertSame(boom, h.turnOutcomes.single().second)
    }

    private fun transcriptTexts(h: ChatPanelTestHarness.Harness): List<String> {
        var texts: List<String> = emptyList()
        SwingUtilities.invokeAndWait {
            texts =
                ChatPanelTestHarness
                    .findAll(h.panel.root, JEditorPane::class.java)
                    .map { pane -> pane.document.getText(0, pane.document.length).trim() }
        }
        return texts
    }

    private companion object {
        const val BACKEND_ID = "ollama"
        const val REFUSAL = "AI is turned off in Burp for this test backend."
    }
}
