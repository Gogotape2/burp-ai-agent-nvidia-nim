package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/**
 * Phase 29 / D-06, UI-SPEC PC-5 and PC-6 — the store build's Ollama card. Its CLI command row and the
 * Open CLI button are full-only (they arrive as the full build's OllamaCliContribution), so the core
 * card lists the HTTP rows only, with Test connection moved under the base URL as on the other HTTP
 * cards (Q1), and the model tooltip no longer promises a CLI fallback the store build lacks (C-N10).
 */
class OllamaCardLayoutTest {
    @Test
    fun theStoreOllamaCardListsTheS7RowsInOrder() {
        onEdt {
            val card = ollamaCard()
            assertEquals(PC5_LABELS, rowLabels(card))
            assertEquals(Insets(8, 8, 8, 8), (card.border as EmptyBorder).borderInsets, "card border stays sectionPad")
        }
    }

    @Test
    fun testConnectionIsTheOnlyButtonAndSitsUnderTheBaseUrl() {
        onEdt {
            val card = ollamaCard()
            // Labelled buttons only: the headers field's JScrollPane carries unlabelled scrollbar arrow buttons.
            val buttons = descendants(card).filterIsInstance<JButton>().filter { it.text.isNotEmpty() }
            assertEquals(listOf("Test connection"), buttons.map { it.text }, "the store Ollama card has no Open CLI")
            val layout = card.layout as GridBagLayout
            val buttonRow = card.components.single { child -> descendants(child).contains(buttons.single()) }
            val row = layout.getConstraints(buttonRow).gridy
            assertTrue(row > rowOf(card, "Ollama base URL"), "Test connection follows the base URL row")
            assertTrue(row < rowOf(card, "Ollama API key (Bearer)"), "Test connection precedes the API key row")
        }
    }

    @Test
    fun thereIsNoOllamaCliRow() {
        onEdt {
            val labels = descendants(ollamaCard()).filterIsInstance<JLabel>().map { it.text }
            assertTrue("Ollama CLI command" !in labels, "the CLI row is full-only: $labels")
        }
    }

    @Test
    fun theModelTooltipIsCn10() {
        onEdt {
            val card = ollamaCard()
            val label = card.components.filterIsInstance<JLabel>().single { it.text == "Ollama model" }
            val field = card.components[card.components.indexOf(label) + 1] as JComponent
            assertEquals("Model name for Ollama HTTP backend. If empty, a default model is used.", field.toolTipText)
        }
    }

    private fun ollamaCard(): JPanel = requireNotNull(BackendConfigPanel().cardFor("ollama")) { "no ollama card" }

    private fun rowLabels(card: JPanel): List<String> = card.components.filterIsInstance<JLabel>().map { it.text }.filter { it.isNotEmpty() }

    private fun rowOf(
        card: JPanel,
        label: String,
    ): Int {
        val layout = card.layout as GridBagLayout
        return layout.getConstraints(card.components.filterIsInstance<JLabel>().single { it.text == label }).gridy
    }

    private fun descendants(root: Component): List<Component> =
        listOf(root) + ((root as? Container)?.components?.flatMap { descendants(it) } ?: emptyList())

    private fun onEdt(block: () -> Unit) {
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                block()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it }
    }

    private companion object {
        // UI-SPEC S7, store order (PC-5).
        val PC5_LABELS =
            listOf(
                "Ollama model",
                "Ollama base URL",
                "Ollama API key (Bearer)",
                "Ollama extra headers",
                "Ollama timeout (seconds)",
                "Ollama serve command",
                "Auto-start Ollama server",
            )
    }
}
