package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/** RED skeleton (29-14 Task 1). */
class CliSettings(
    private val store: PluginSettingsStore?,
) {
    fun command(backendId: String): String = ""

    fun timeoutSeconds(): Int = 0

    companion object {
        const val KEY_CODEX_CMD = "codex.cmd"
        const val KEY_GEMINI_CMD = "gemini.cmd"
        const val KEY_OPENCODE_CMD = "opencode.cmd"
        const val KEY_CLAUDE_CMD = "claude.cmd"
        const val KEY_COPILOT_CMD = "copilot.cmd"
        const val KEY_OLLAMA_CLI_CMD = "ollama.cli.cmd"
        const val KEY_CLI_TIMEOUT = "cli.timeoutSeconds"

        fun keyFor(backendId: String): String? = null

        fun defaultCommand(backendId: String): String = ""
    }
}
