package com.six2dez.burp.aiagent.full.cli

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.Box
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder

/**
 * Phase 29 / D-07, UI-SPEC PC-7 and PC-8: the five CLI cards and the Ollama CLI block reach the full
 * build's settings window as `SettingsContribution` providers, and each reproduces its 1.0.1 card
 * byte for byte (S6 table, button rules, C-N11). A copy that drifts by one character is a defect.
 */
class CliContributionUiTest {
    private val prefs = InMemoryPreferences()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val store: PluginSettingsStore
    private val testedIds = mutableListOf<String>()

    init {
        whenever(api.persistence().preferences()).thenReturn(prefs)
        store = AgentSettingsRepository(api).pluginSettings()
    }

    private val context =
        SettingsContributionContext(
            api = api,
            store = store,
            coreSettings = { TestSettings.baselineSettings() },
            dialogParent = { null },
            testConnection = { testedIds += it },
        )

    @Test
    fun theFullBuildContributesSixBackendCardBlocks() {
        val contributions = Plugins.load(SettingsContribution::class.java)
        assertEquals(6, contributions.size, "5 CLI cards plus the Ollama CLI block, got ${contributions.map { it.javaClass.name }}")
        assertTrue(contributions.all { it.slot == SettingsSlot.BACKEND_CARD })
        assertEquals(
            setOf("codex-cli", "gemini-cli", "opencode-cli", "claude-cli", "copilot-cli", "ollama"),
            contributions.mapNotNull { it.backendId }.toSet(),
        )
        val sectionIds = contributions.map { it.sectionId }
        assertTrue(sectionIds.none { it.isBlank() }, "sectionIds are non-blank: $sectionIds")
        assertEquals(sectionIds.size, sectionIds.toSet().size, "sectionIds are unique: $sectionIds")
        contributions.forEach { assertEquals("cli.${it.backendId}", it.sectionId) }
    }

    @Test
    fun everyCliCardMatchesTheS6Table() {
        S6.forEach { row ->
            onEdt {
                val panel = row.contribution().createComponent(context) as JPanel
                val id = row.backendId
                assertTrue(panel.layout is GridBagLayout, "$id: a formGrid()")
                assertEquals(row.padding, (panel.border as EmptyBorder).borderInsets, "$id: card padding")
                val rowLabels = descendants(panel).filterIsInstance<JLabel>().map { it.text }.filter { it.isNotEmpty() }
                assertEquals(listOf(row.label), rowLabels, "$id: row label")
                val field = descendants(panel).filterIsInstance<JTextField>().single()
                assertEquals(row.tooltip, field.toolTipText, "$id: field tooltip")
                assertButtons(id, panel, listOf("Open CLI", "Test connection"))
                val trailing = panel.components.last()
                if (row.spacerRow) {
                    assertTrue(trailing is Box.Filler, "$id: an 8 px trailing spacer row")
                    assertEquals(DesignTokens.Spacing.sm, trailing.preferredSize.height, "$id: spacer height")
                } else {
                    assertFalse(trailing is Box.Filler, "$id: no spacer row")
                }
            }
        }
    }

    @Test
    fun theOllamaCliBlockMatchesPc7() {
        onEdt {
            val contribution = OllamaCliContribution()
            assertEquals("ollama", contribution.backendId)
            assertEquals("cli.ollama", contribution.sectionId)
            assertEquals(setOf("ollama.cli.cmd"), contribution.ownedKeys())
            val block = contribution.createComponent(context) as JPanel
            assertTrue(block.layout is GridBagLayout, "the block is its own formGrid()")
            assertEquals(Insets(0, 8, 8, 8), (block.border as EmptyBorder).borderInsets, "block padding")
            val rowLabels = descendants(block).filterIsInstance<JLabel>().map { it.text }.filter { it.isNotEmpty() }
            assertEquals(listOf("Ollama CLI command"), rowLabels)
            assertEquals(C_N11, descendants(block).filterIsInstance<JTextField>().single().toolTipText)
            assertButtons("ollama", block, listOf("Open CLI"))
        }
    }

    @Test
    fun testConnectionOnACliCardRunsTheCoreFlowForItsId() {
        onEdt {
            S6.forEach { row ->
                val panel = row.contribution().createComponent(context)
                descendants(panel).filterIsInstance<JButton>().single { it.text == "Test connection" }.doClick()
            }
        }
        assertEquals(S6.map { it.backendId }, testedIds)
    }

    @Test
    fun aCardShowsCollectsAndPersistsOnlyItsOwnKey() {
        prefs.strings["codex.cmd"] = "codex exec"
        onEdt {
            (S6.map { it.contribution() } + OllamaCliContribution()).forEach { contribution ->
                val panel = contribution.createComponent(context)
                val field = descendants(panel).filterIsInstance<JTextField>().single()
                if (contribution.backendId == "codex-cli") assertEquals("codex exec", field.text, "initial value from the store")
                field.text = "  ${contribution.backendId} --edited  "
                val snapshot = contribution.collect()
                val recorder = RecordingStore(store)
                contribution.persist(snapshot, recorder)
                assertEquals(contribution.ownedKeys(), recorder.written.toSet(), "${contribution.backendId}: persist writes its own key only")
                assertEquals(
                    "${contribution.backendId} --edited",
                    prefs.strings[contribution.ownedKeys().single()],
                    "${contribution.backendId}: trimmed like the 1.0.1 card",
                )
                contribution.applyToUi(contribution.defaults())
                assertEquals(expectedDefault(contribution), field.text, "${contribution.backendId}: Restore defaults")
            }
        }
    }

    @Test
    fun shellQuoteKeepsThe101Quoting() {
        assertEquals("''", CliTerminalLauncher.shellQuote(""))
        assertEquals("codex", CliTerminalLauncher.shellQuote("codex"))
        assertEquals("'codex chat; exec bash'", CliTerminalLauncher.shellQuote("codex chat; exec bash"))
        assertEquals("'it'\"'\"'s'", CliTerminalLauncher.shellQuote("it's"))
    }

    private fun expectedDefault(contribution: SettingsContribution): String =
        when (contribution.backendId) {
            "codex-cli" -> "codex chat"
            "gemini-cli" -> "gemini --output-format text --model gemini-2.5-flash --yolo"
            "opencode-cli" -> "opencode"
            "claude-cli" -> "claude"
            "copilot-cli" -> "copilot"
            else -> "ollama run llama3.1"
        }

    private fun assertButtons(
        id: String,
        root: JComponent,
        labels: List<String>,
    ) {
        val buttons = descendants(root).filterIsInstance<JButton>()
        assertEquals(labels, buttons.map { it.text }, "$id: button row")
        buttons.forEach { button ->
            assertEquals(BUTTON_TOOLTIPS.getValue(button.text), button.toolTipText, "$id: ${button.text} tooltip")
            assertEquals(DesignTokens.Typography.body, button.font, "$id: ${button.text} font")
        }
        if (buttons.size == 2) {
            val row = buttons.first().parent
            val gap = row.components[1]
            assertTrue(gap is Box.Filler, "$id: a rigid gap between the buttons")
            assertEquals(DesignTokens.Spacing.sm, gap.preferredSize.width, "$id: Spacing.sm apart")
        }
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

    private class RecordingStore(
        private val delegate: PluginSettingsStore,
    ) : PluginSettingsStore by delegate {
        val written = mutableListOf<String>()

        override fun setString(
            key: String,
            value: String,
        ) {
            written += key
            delegate.setString(key, value)
        }

        override fun setBoolean(
            key: String,
            value: Boolean,
        ) {
            written += key
            delegate.setBoolean(key, value)
        }

        override fun setInteger(
            key: String,
            value: Int,
        ) {
            written += key
            delegate.setInteger(key, value)
        }
    }

    private data class S6Row(
        val backendId: String,
        val label: String,
        val tooltip: String,
        val padding: Insets,
        val spacerRow: Boolean,
        val contribution: () -> SettingsContribution,
    )

    private companion object {
        const val C_N11 =
            "Command used to launch Ollama CLI with a model. If Ollama model is empty, the model in this command is used."

        val BUTTON_TOOLTIPS =
            mapOf(
                "Open CLI" to "Open a terminal with the configured command and MCP tools access.",
                "Test connection" to "Run backend health check with current settings.",
            )

        val TOP_AND_SIDES = Insets(8, 8, 0, 8)
        val ALL_SIDES = Insets(8, 8, 8, 8)

        // UI-SPEC S6 table, verbatim.
        val S6 =
            listOf(
                S6Row("codex-cli", "Codex CLI command", "Command used to launch Codex CLI.", TOP_AND_SIDES, true) {
                    CodexCliContribution()
                },
                S6Row("gemini-cli", "Gemini CLI command", "Command used to launch Gemini CLI.", TOP_AND_SIDES, true) {
                    GeminiCliContribution()
                },
                S6Row(
                    "opencode-cli",
                    "OpenCode CLI command",
                    "Command used to launch OpenCode CLI with the model (e.g., opencode --model anthropic/claude-sonnet-4-5).",
                    ALL_SIDES,
                    false,
                ) { OpenCodeCliContribution() },
                S6Row("claude-cli", "Claude Code command", "Command used to launch Claude Code CLI (e.g., claude).", TOP_AND_SIDES, true) {
                    ClaudeCliContribution()
                },
                S6Row("copilot-cli", "Copilot CLI command", "Command used to launch Copilot CLI (e.g., copilot).", TOP_AND_SIDES, true) {
                    CopilotCliContribution()
                },
            )
    }
}
