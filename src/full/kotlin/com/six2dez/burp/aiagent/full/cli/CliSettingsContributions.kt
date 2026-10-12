package com.six2dez.burp.aiagent.full.cli

import com.six2dez.burp.aiagent.backends.cli.CliSettings
import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.addSpacerRow
import com.six2dez.burp.aiagent.ui.design.applyFieldStyle
import com.six2dez.burp.aiagent.ui.design.formGrid
import com.six2dez.burp.aiagent.ui.panels.buildButtonRowPanel
import com.six2dez.burp.aiagent.ui.panels.buildTestConnectionButton
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.border.EmptyBorder

/*
 * Phase 29 / D-06, D-07 — the CLI plug-in's settings UI. Each CLI backend card and the Ollama card's
 * CLI block reach the full build's settings window as a SettingsContribution (BACKEND_CARD slot) listed
 * in META-INF/services/com.six2dez.burp.aiagent.spi.SettingsContribution; the store build has neither
 * the classes nor the services file. Each card reproduces its 1.0.1 card byte for byte (UI-SPEC S6, PC-8)
 * and stores its command under its 1.0.1 key through PluginSettingsStore (D-11).
 */

/** What a CLI command contribution reads off its field: the trimmed command. */
data class CliCommandSnapshot(
    val command: String,
) : ContributionSnapshot

/**
 * One CLI command field with its 1.0.1 card around it. Subclasses fix the backend id and build the
 * card; the field, its value, Save, Restore defaults and the key it owns are handled here.
 *
 * The one owned key is the backend's 1.0.1 command key ([CliSettings.keyFor]); [persist] writes it and
 * nothing else.
 */
abstract class CliCommandContribution(
    final override val backendId: String,
    private val fieldTooltip: String,
) : SettingsContribution {
    final override val sectionId: String = "cli.$backendId"
    final override val slot: SettingsSlot = SettingsSlot.BACKEND_CARD

    private val key: String = requireNotNull(CliSettings.keyFor(backendId)) { "no CLI key for $backendId" }

    /** Built in [createComponent] on the EDT; the host never calls another UI member before it. */
    protected lateinit var field: JTextField

    final override fun ownedKeys(): Set<String> = setOf(key)

    final override fun createComponent(context: SettingsContributionContext): JComponent {
        field =
            JTextField(CliSettings(context.store).command(backendId)).apply {
                applyFieldStyle(this)
                toolTipText = fieldTooltip
            }
        return buildCard(context)
    }

    /** The card around [field], exactly as 1.0.1 laid it out. */
    protected abstract fun buildCard(context: SettingsContributionContext): JPanel

    final override fun collect(): ContributionSnapshot = CliCommandSnapshot(field.text.trim())

    final override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {
        store.setString(key, (snapshot as CliCommandSnapshot).command)
    }

    final override fun defaults(): ContributionSnapshot = CliCommandSnapshot(CliSettings.defaultCommand(backendId))

    final override fun applyToUi(snapshot: ContributionSnapshot) {
        field.text = (snapshot as CliCommandSnapshot).command
    }
}

/** A 1.0.1 single-field CLI card: label, command field, [Open CLI] [Test connection], 8 px spacer row. */
abstract class SingleFieldCliCardContribution(
    backendId: String,
    private val rowLabel: String,
    fieldTooltip: String,
) : CliCommandContribution(backendId, fieldTooltip) {
    final override fun buildCard(context: SettingsContributionContext): JPanel = buildSingleFieldPanelWithCli(context, rowLabel, field, backendId) { field.text.trim() }
}

class CodexCliContribution : SingleFieldCliCardContribution("codex-cli", "Codex CLI command", "Command used to launch Codex CLI.")

class GeminiCliContribution : SingleFieldCliCardContribution("gemini-cli", "Gemini CLI command", "Command used to launch Gemini CLI.")

class ClaudeCliContribution : SingleFieldCliCardContribution("claude-cli", "Claude Code command", "Command used to launch Claude Code CLI (e.g., claude).")

class CopilotCliContribution : SingleFieldCliCardContribution("copilot-cli", "Copilot CLI command", "Command used to launch Copilot CLI (e.g., copilot).")

/** The 1.0.1 OpenCode card: `sectionPad` on all sides and no spacer row. */
class OpenCodeCliContribution :
    CliCommandContribution(
        "opencode-cli",
        "Command used to launch OpenCode CLI with the model (e.g., opencode --model anthropic/claude-sonnet-4-5).",
    ) {
    override fun buildCard(context: SettingsContributionContext): JPanel = buildOpenCodePanel(context, field)
}

/**
 * The full build's block under the core Ollama card (UI-SPEC S7 rows 9-10, PC-7): "Ollama CLI command"
 * (tooltip C-N11) and an [Open CLI] button. Test connection stays on the core card. The block is its
 * own formGrid(), so its field column may start at a different x than the core rows (accepted
 * residual). The command also names the model a blank "Ollama model" falls back to, through
 * [OllamaCliModelHint].
 */
class OllamaCliContribution :
    CliCommandContribution(
        "ollama",
        "Command used to launch Ollama CLI with a model. If Ollama model is empty, the model in this command is used.",
    ) {
    override fun buildCard(context: SettingsContributionContext): JPanel {
        val panel = formGrid()
        panel.border =
            EmptyBorder(0, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad)
        addRowFull(panel, "Ollama CLI command", field)
        addRowFull(panel, "", buildButtonRowPanel(buildOpenCliButton(context, backendId) { field.text.trim() }))
        return panel
    }
}

// The 1.0.1 CLI card builders, moved from the core BackendConfigPanel with their bodies unchanged except
// that Open CLI calls CliTerminalLauncher and Test connection calls the host's flow
// (SettingsContributionContext.testConnection). buildTestConnectionButton and buildButtonRowPanel are
// the core's flavor-neutral builders, shared through associateWith (UI-SPEC PC-8).

internal fun buildSingleFieldPanelWithCli(
    context: SettingsContributionContext,
    labelText: String,
    field: JComponent,
    backendId: String,
    commandProvider: () -> String,
): JPanel {
    val panel = formGrid()
    panel.border = EmptyBorder(DesignTokens.Spacing.sectionPad, DesignTokens.Spacing.sectionPad, 0, DesignTokens.Spacing.sectionPad)
    addRowFull(panel, labelText, field)
    addRowFull(
        panel,
        "",
        buildButtonRowPanel(
            buildOpenCliButton(context, backendId, commandProvider),
            buildTestConnectionButton { context.testConnection(backendId) },
        ),
    )
    addSpacerRow(panel, DesignTokens.Spacing.sm)
    return panel
}

internal fun buildOpenCodePanel(
    context: SettingsContributionContext,
    opencodeCmd: JTextField,
): JPanel {
    val panel = formGrid()
    panel.border =
        EmptyBorder(
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
            DesignTokens.Spacing.sectionPad,
        )
    addRowFull(panel, "OpenCode CLI command", opencodeCmd)
    addRowFull(
        panel,
        "",
        buildButtonRowPanel(
            buildOpenCliButton(context, "opencode-cli", { opencodeCmd.text.trim() }),
            buildTestConnectionButton { context.testConnection("opencode-cli") },
        ),
    )
    return panel
}

internal fun buildOpenCliButton(
    context: SettingsContributionContext,
    backendId: String,
    commandProvider: () -> String,
): JButton =
    JButton("Open CLI").apply {
        font = DesignTokens.Typography.body
        toolTipText = "Open a terminal with the configured command and MCP tools access."
        addActionListener {
            CliTerminalLauncher.openExternalCli(context.api, context.dialogParent(), backendId, commandProvider())
        }
    }
