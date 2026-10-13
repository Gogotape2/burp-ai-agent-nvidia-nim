package com.six2dez.burp.aiagent.full

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.BuildFlags
import com.six2dez.burp.aiagent.buildIdentityLine
import com.six2dez.burp.aiagent.registerExtensionIdentity
import com.six2dez.burp.aiagent.resolveFlavorProfile
import com.six2dez.burp.aiagent.ui.panels.HelpConfigPanel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import java.awt.Component
import java.awt.Container
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingUtilities

/**
 * Phase 29 / UI-SPEC PC-15 (S25, C-N12) — the full-classpath half of the Help build caption pin.
 *
 * The identity line of the resolved profile is the logged banner and ends with the full profile's
 * label. Plan 29-17 relabelled the full build (PC-14) and pins the literal line here (C-N12): the
 * banner and the Help caption both read "Custom AI Agent <version> (GitHub full build)". The class name differs from the store HelpBuildCaptionTest so the FQNs do not collide on
 * this classpath, which also carries the store test output.
 */
class FullHelpBuildCaptionTest {
    @Test
    fun theFullIdentityLineIsTheLoggedBannerAndEndsWithTheFullLabel() {
        val profile = resolveFlavorProfile()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        registerExtensionIdentity(api, profile)
        val banner = argumentCaptor<String>()
        verify(api.logging(), times(1)).logToOutput(banner.capture())

        val line = buildIdentityLine(profile)
        assertEquals(banner.firstValue, line, "C-N12: the caption and the S3 banner are one string.")
        assertTrue(
            line.endsWith("(" + FullFlavorProfile().label + ")"),
            "S25: the full label closes the line. Line: $line",
        )
        assertEquals("Custom AI Agent ${BuildFlags.VERSION} (GitHub full build)", line, "C-N12: the exact full identity line")
    }

    @Test
    fun theFullHelpCaptionIsTheExactFullIdentityLine() {
        val expected = "Custom AI Agent ${BuildFlags.VERSION} (GitHub full build)"
        lateinit var section: JPanel
        SwingUtilities.invokeAndWait {
            section = HelpConfigPanel(dialogParentProvider = { null }, buildIdentity = buildIdentityLine(resolveFlavorProfile())).build()
        }
        lateinit var captions: List<String>
        SwingUtilities.invokeAndWait { captions = labelsUnder(section).map { it.text.orEmpty() }.filter { it.startsWith("Custom AI Agent ") } }
        assertEquals(listOf(expected), captions, "PC-15: the Help section shows the full identity line once")
    }

    private fun labelsUnder(root: Component): List<JLabel> {
        val found = mutableListOf<JLabel>()

        fun walk(c: Component) {
            if (c is JLabel) found.add(c)
            if (c is Container) c.components.forEach { walk(it) }
        }
        walk(root)
        return found
    }
}
