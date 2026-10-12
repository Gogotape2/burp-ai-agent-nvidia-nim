package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/**
 * Phase 29 / D-06, D-11 — the CLI plug-in's own settings, read through [PluginSettingsStore].
 *
 * The keys and defaults moved here from the core `AgentSettings` companion with their 1.0.1 names and
 * values, so an upgraded full install reads every value where 1.0.1 left it. The store build never
 * reads, writes or deletes these keys (D-08).
 *
 * Read rules:
 * - An absent key reads as its 1.0.1 default.
 * - A stored value is trimmed and returned as stored, blank included. A blank command is what the user
 *   saved from an empty field; [CliBackend.configurationError] then reports it with the 1.0.1 message
 *   ("Codex command is empty." and the others) instead of silently launching the default.
 * - The legacy Gemini default (`gemini --output-format text --model gemini-2.5-flash`) reads as the
 *   current default. The core schema-v2 migration used to rewrite it; the plug-in normalizes on read
 *   and writes nothing.
 * - `cli.timeoutSeconds` reads clamped to [MIN_TIMEOUT_SECONDS]..[MAX_TIMEOUT_SECONDS], absent as
 *   [Defaults.CLI_PROCESS_TIMEOUT_SECONDS].
 *
 * With a null [store] (a backend before the registry applied one) every read is the default.
 */
class CliSettings(
    private val store: PluginSettingsStore?,
) {
    /** The configured command for [backendId], or "" for an id the CLI plug-in does not own. */
    fun command(backendId: String): String {
        val key = keyFor(backendId)
        val stored = key?.let { store?.getString(it) }
        return when {
            key == null -> ""
            stored == null -> defaultCommand(backendId)
            key == KEY_GEMINI_CMD -> normalizeLegacyGeminiCmd(stored.trim())
            else -> stored.trim()
        }
    }

    /** The CLI process timeout in seconds, clamped to the watchdog range. */
    fun timeoutSeconds(): Int =
        (store?.getInteger(KEY_CLI_TIMEOUT) ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS)
            .coerceIn(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)

    companion object {
        const val KEY_CODEX_CMD = "codex.cmd"
        const val KEY_GEMINI_CMD = "gemini.cmd"
        const val KEY_OPENCODE_CMD = "opencode.cmd"
        const val KEY_CLAUDE_CMD = "claude.cmd"
        const val KEY_COPILOT_CMD = "copilot.cmd"
        const val KEY_OLLAMA_CLI_CMD = "ollama.cli.cmd"
        const val KEY_CLI_TIMEOUT = "cli.timeoutSeconds"

        /** WR-02 / REL-04: a sub-30 s watchdog kills slow-starting CLIs; an hour is the ceiling. */
        const val MIN_TIMEOUT_SECONDS = 30
        const val MAX_TIMEOUT_SECONDS = 3600

        const val DEFAULT_CODEX_CMD = "codex chat"
        const val DEFAULT_GEMINI_CMD = "gemini --output-format text --model gemini-2.5-flash --yolo"
        const val DEFAULT_OPENCODE_CMD = "opencode"
        const val DEFAULT_CLAUDE_CMD = "claude"
        const val DEFAULT_COPILOT_CMD = "copilot"
        const val DEFAULT_OLLAMA_CLI_CMD = "ollama run llama3.1"

        private const val LEGACY_GEMINI_DEFAULT = "gemini --output-format text --model gemini-2.5-flash"

        private val COMMAND_KEYS =
            mapOf(
                "codex-cli" to KEY_CODEX_CMD,
                "gemini-cli" to KEY_GEMINI_CMD,
                "opencode-cli" to KEY_OPENCODE_CMD,
                "claude-cli" to KEY_CLAUDE_CMD,
                "copilot-cli" to KEY_COPILOT_CMD,
                "ollama" to KEY_OLLAMA_CLI_CMD,
            )

        private val DEFAULT_COMMANDS =
            mapOf(
                "codex-cli" to DEFAULT_CODEX_CMD,
                "gemini-cli" to DEFAULT_GEMINI_CMD,
                "opencode-cli" to DEFAULT_OPENCODE_CMD,
                "claude-cli" to DEFAULT_CLAUDE_CMD,
                "copilot-cli" to DEFAULT_COPILOT_CMD,
                "ollama" to DEFAULT_OLLAMA_CLI_CMD,
            )

        /** The 1.0.1 preference key holding [backendId]'s command, or null for an id the plug-in does not own. */
        fun keyFor(backendId: String): String? = COMMAND_KEYS[backendId]

        /** The 1.0.1 default command for [backendId], or "" for an id the plug-in does not own. */
        fun defaultCommand(backendId: String): String = DEFAULT_COMMANDS[backendId].orEmpty()

        internal fun normalizeLegacyGeminiCmd(raw: String): String = if (raw == LEGACY_GEMINI_DEFAULT) DEFAULT_GEMINI_CMD else raw
    }
}
