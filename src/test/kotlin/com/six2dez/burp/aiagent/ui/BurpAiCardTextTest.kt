package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * Quick task 261017-hvd: the Burp AI card must state only what the code enforces. That is Burp's
 * per-extension "Use AI" setting and the Extensions > Installed > Custom AI Agent > Use AI path from
 * README.md Requirements, with no Burp edition claim.
 */
class BurpAiCardTextTest {
    @Test
    fun theBurpAiCardStatesOnlyThePerExtensionUseAiRequirement() {
        onEdt {
            val card = requireNotNull(BackendConfigPanel().cardFor("burp-ai")) { "no burp-ai card" }
            val text = descendants(card).filterIsInstance<JTextArea>().single().text
            assertTrue(
                text.startsWith("Burp AI uses the built-in AI provider. No configuration needed."),
                "first sentence unchanged: $text",
            )
            assertTrue(
                text.contains("AI requests need Burp's 'Use AI' setting enabled for this extension."),
                "per-extension Use AI line: $text",
            )
            assertTrue(
                text.contains("Extensions > Installed > Custom AI Agent > Use AI."),
                "Installed path from README.md Requirements: $text",
            )
            assertFalse(text.contains("Professional"), "no Burp edition claim: $text")
            assertFalse(text.contains("Extensions > Settings"), "no stale Settings path: $text")
        }
    }

    private fun descendants(root: Component): List<Component> = listOf(root) + ((root as? Container)?.components?.flatMap { descendants(it) } ?: emptyList())

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
}
