package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.config.CustomPromptDefinition
import com.six2dez.burp.aiagent.config.CustomPromptTag
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.mockito.MockedStatic
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.times
import java.awt.Component
import java.awt.Container
import javax.swing.JCheckBox
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.JTextField

/**
 * Phase 34 / D-05: CustomPromptEditDialog.show is a modal dialog re-prompt loop that waits on user
 * input, not a string scan. These cases pin its three exits across the loop rewrite: a cancel
 * returns null, blank input warns and prompts again, valid input returns a definition (keeping the
 * id when editing).
 *
 * JOptionPane is replaced with a static mock, so no dialog is ever shown under
 * -Djava.awt.headless=true. Static mocks are thread-local, so show() runs on the test thread.
 * Every case stubs showConfirmDialog explicitly: an unstubbed static int method answers 0, which is
 * OK_OPTION.
 */
class CustomPromptEditDialogTest {
    @Test
    fun aCancelReturnsNull() {
        Mockito.mockStatic(JOptionPane::class.java).use { mocked ->
            mocked.stubConfirm { JOptionPane.CANCEL_OPTION }

            val result = CustomPromptEditDialog.show(JPanel(), null)

            assertNull(result, "A cancelled dialog must return null")
            mocked.verifyConfirmCount(1)
            mocked.verifyWarningCount(0)
        }
    }

    @Test
    fun blankInputWarnsAndPromptsAgain() {
        Mockito.mockStatic(JOptionPane::class.java).use { mocked ->
            var prompts = 0
            mocked.stubConfirm { panel ->
                prompts++
                if (prompts == 2) {
                    // Second prompt: the user fills in the form, padded so trimming is observable.
                    panel.firstOf<JTextField>().text = "  My prompt  "
                    panel.firstOf<JTextArea>().text = "  Explain this request.  "
                    panel.allOf<JCheckBox>().first { it.text == "HTTP request/response menu" }.isSelected = true
                    panel.allOf<JCheckBox>().first { it.text == "Scanner issue menu" }.isSelected = false
                }
                // First prompt: OK with the fields as built (a blank title for a new prompt).
                JOptionPane.OK_OPTION
            }

            val result = CustomPromptEditDialog.show(JPanel(), null)

            assertNotNull(result, "Valid input on the second prompt must return a definition")
            assertEquals("My prompt", result!!.title)
            assertEquals("Explain this request.", result.promptText)
            assertEquals(setOf(CustomPromptTag.HTTP_SELECTION), result.tags)
            mocked.verifyConfirmCount(2)
            mocked.verifyWarningCount(1)
        }
    }

    @Test
    fun editingKeepsTheExistingId() {
        val existing =
            CustomPromptDefinition(
                id = "existing-id-123",
                title = "Existing",
                promptText = "Existing prompt text",
                tags = setOf(CustomPromptTag.SCANNER_ISSUE),
                showInContextMenu = false,
                isFavorite = true,
            )
        Mockito.mockStatic(JOptionPane::class.java).use { mocked ->
            mocked.stubConfirm { JOptionPane.OK_OPTION }

            val result = CustomPromptEditDialog.show(JPanel(), existing)

            assertEquals(existing, result, "Editing and accepting at once must return the same definition, id included")
            assertEquals("existing-id-123", result!!.id)
            mocked.verifyConfirmCount(1)
            mocked.verifyWarningCount(0)
        }
    }

    private fun MockedStatic<JOptionPane>.stubConfirm(answer: (Container) -> Int) {
        `when`<Int> {
            JOptionPane.showConfirmDialog(anyOrNull<Component>(), any<Any>(), anyOrNull<String>(), any<Int>(), any<Int>())
        }.thenAnswer { invocation -> answer(invocation.getArgument(1) as Container) }
    }

    private fun MockedStatic<JOptionPane>.verifyConfirmCount(count: Int) {
        verify(
            { JOptionPane.showConfirmDialog(anyOrNull<Component>(), any<Any>(), anyOrNull<String>(), any<Int>(), any<Int>()) },
            times(count),
        )
    }

    private fun MockedStatic<JOptionPane>.verifyWarningCount(count: Int) {
        verify(
            { JOptionPane.showMessageDialog(anyOrNull<Component>(), any<Any>(), anyOrNull<String>(), any<Int>()) },
            times(count),
        )
    }

    private inline fun <reified T : Component> Container.allOf(): List<T> = descendants().filterIsInstance<T>()

    private fun Container.descendants(): List<Component> {
        val found = mutableListOf<Component>()
        for (child in components) {
            found += child
            if (child is Container) found += child.descendants()
        }
        return found
    }

    private inline fun <reified T : Component> Container.firstOf(): T = allOf<T>().first()
}
