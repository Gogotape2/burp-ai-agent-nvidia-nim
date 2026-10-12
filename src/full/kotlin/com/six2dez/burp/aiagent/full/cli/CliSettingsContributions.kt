package com.six2dez.burp.aiagent.full.cli

import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import javax.swing.JComponent
import javax.swing.JPanel

/** RED skeleton (29-14 Task 1). */
data class CliCommandSnapshot(
    val command: String,
) : ContributionSnapshot

/** RED skeleton (29-14 Task 1). */
abstract class CliCommandContribution(
    final override val backendId: String,
    private val key: String,
) : SettingsContribution {
    final override val sectionId: String = "cli.$backendId"
    final override val slot: SettingsSlot = SettingsSlot.BACKEND_CARD

    override fun ownedKeys(): Set<String> = setOf(key)

    override fun createComponent(context: SettingsContributionContext): JComponent = JPanel()

    override fun collect(): ContributionSnapshot = CliCommandSnapshot("")

    override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {}

    override fun defaults(): ContributionSnapshot = CliCommandSnapshot("")

    override fun applyToUi(snapshot: ContributionSnapshot) {}
}

class CodexCliContribution : CliCommandContribution("codex-cli", "codex.cmd")

class GeminiCliContribution : CliCommandContribution("gemini-cli", "gemini.cmd")

class OpenCodeCliContribution : CliCommandContribution("opencode-cli", "opencode.cmd")

class ClaudeCliContribution : CliCommandContribution("claude-cli", "claude.cmd")

class CopilotCliContribution : CliCommandContribution("copilot-cli", "copilot.cmd")

class OllamaCliContribution : CliCommandContribution("ollama", "ollama.cli.cmd")
