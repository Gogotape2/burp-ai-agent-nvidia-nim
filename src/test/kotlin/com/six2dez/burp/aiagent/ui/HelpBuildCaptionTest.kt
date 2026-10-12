package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.buildIdentityLine
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.registerExtensionIdentity
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.panels.HelpConfigPanel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Container
import java.awt.Insets
import javax.swing.JEditorPane
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/**
 * Phase 29 / UI-SPEC PC-15 (S25, C-N12, Q7) — the Help tab build caption, store classpath.
 *
 * One function builds the identity line for both the Output banner and the caption, and the caption is
 * a plain caption-role label in the Help section's footer. FullHelpBuildCaptionTest (src/fullTest) pins
 * the same on the full classpath; the class names differ so the two FQNs never collide there.
 */
class HelpBuildCaptionTest {
    @Test
    fun theStoreIdentityLineIsTheLoggedBannerAndEndsWithTheStoreLabel() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        registerExtensionIdentity(api, StoreFlavorProfile())
        val banner = argumentCaptor<String>()
        verify(api.logging(), times(1)).logToOutput(banner.capture())

        val line = buildIdentityLine(StoreFlavorProfile())
        assertEquals(banner.firstValue, line, "C-N12: the caption and the S3 banner are one string.")
        assertTrue(line.endsWith("(BApp Store build)"), "S25: the store label closes the line. Line: $line")
        assertTrue(line.length < 50, "S25 overflow: the caption stays under 50 characters. Line: $line")
    }

    @Test
    fun theHelpSectionEndsWithTheCaptionInItsFooter() {
        val identity = "Custom AI Agent 9.9.9 (caption test)"
        lateinit var section: JPanel
        SwingUtilities.invokeAndWait {
            section = HelpConfigPanel(dialogParentProvider = { null }, buildIdentity = identity).build()
        }
        val captions = labelsUnder(section).filter { it.text == identity }
        assertEquals(1, captions.size, "S25: exactly one caption.")
        val caption = captions.single()

        val footer = caption.parent as JPanel
        val layout = footer.layout as BorderLayout
        assertEquals(BorderLayout.SOUTH, layout.getConstraints(caption), "S25: the caption sits at SOUTH.")
        assertTrue(layout.getLayoutComponent(BorderLayout.CENTER) is JEditorPane, "S25: the help pane is CENTER.")
        assertEquals(DesignTokens.Colors.surface, footer.background, "S25: the content panel is surface.")

        assertEquals(DesignTokens.Typography.caption, caption.font, "S25: caption role.")
        assertEquals(DesignTokens.Colors.onSurfaceVariant, caption.foreground, "S25: onSurfaceVariant.")
        val border = caption.border as EmptyBorder
        val pad = DesignTokens.Spacing.sectionPad
        assertEquals(Insets(0, pad, pad, pad), border.borderInsets, "S25: 0 top, sectionPad sides and bottom.")
        assertTrue(labelsUnder(section).any { it.text == "Help" }, "The section title is unchanged.")
    }

    @Test
    fun aHeadlessSettingsPanelShowsItsBuildIdentityAsTheHelpCaption() {
        val identity = "Custom AI Agent 9.9.9 (panel test)"
        val panel = newPanel(identity)
        try {
            lateinit var matches: List<JLabel>
            SwingUtilities.invokeAndWait { matches = labelsUnder(panel.helpTab).filter { it.text == identity } }
            assertEquals(1, matches.size, "PC-15: SettingsPanel passes buildIdentity down to the Help caption.")
        } finally {
            panel.shutdown()
        }
    }

    private fun newPanel(identity: String): SettingsPanel {
        val preferences = inMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("ollama"))
        return SettingsPanel(
            api = api,
            settingsRepo = AgentSettingsRepository(api),
            backends = backends,
            supervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            audit = mock<AuditLogger>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            mcpSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            passiveAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            activeAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            buildIdentity = identity,
            contributions = emptyList(),
        )
    }

    private fun inMemoryPreferences(): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
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
