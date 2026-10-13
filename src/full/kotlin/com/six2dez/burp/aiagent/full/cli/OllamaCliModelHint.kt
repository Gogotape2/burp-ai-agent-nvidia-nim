package com.six2dez.burp.aiagent.full.cli

import com.six2dez.burp.aiagent.backends.cli.CliSettings
import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor

/**
 * Phase 29 / D-06, user decision 2026-10-09 — in the full build a blank "Ollama model" still falls
 * back to the model named in the Ollama CLI command, as in 1.0.1. The command is a CLI plug-in key
 * (`ollama.cli.cmd`), so the fallback lives here and reaches the core supervisor through
 * [BackendModelHint]; the store build, which has no Ollama CLI command, uses the core default.
 *
 * The parse is the 1.0.1 `AgentSupervisor.parseOllamaModelFromCli`, unchanged: the token after `run`
 * unless it is a flag.
 */
class OllamaCliModelHint : BackendModelHint {
    override fun defaultModel(
        backendId: String,
        store: PluginSettingsStore,
    ): String? {
        if (backendId != OLLAMA_ID) return null
        return parseOllamaModelFromCli(CliSettings(store).command(OLLAMA_ID).trim())
    }

    // ReturnCount, MagicNumber: the 1.0.1 body, moved verbatim from AgentSupervisor (where both were
    // baselined); suppressed here because ADR-17 forbids new baseline entries.
    @Suppress("ReturnCount", "MagicNumber")
    private fun parseOllamaModelFromCli(cmd: String): String? {
        if (cmd.isBlank()) return null
        val parts = AgentSupervisor.tokenizeCommand(cmd)
        val runIdx = parts.indexOf("run")
        if (runIdx >= 0 && runIdx + 1 < parts.size) {
            val candidate = parts[runIdx + 1]
            return if (candidate.startsWith("-")) null else candidate
        }
        if (parts.size >= 3 && parts[0] == "ollama" && parts[1] == "run") {
            return parts[2]
        }
        return null
    }

    private companion object {
        const val OLLAMA_ID = "ollama"
    }
}
