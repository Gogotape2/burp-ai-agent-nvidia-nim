package com.six2dez.burp.aiagent.full.cli

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.cli.CliSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.full.FullAiAccessPolicy
import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 / D-06, D-11: the full build's CLI plug-in owns the CLI preference keys under their 1.0.1
 * names. An upgraded install must read every value where 1.0.1 left it, the legacy Gemini default is
 * still normalized (the core migration no longer does it), and the CLI timeout keeps its 30..3600
 * clamp (BUILD-04 precision edge).
 */
class CliSettingsTest {
    private val prefs = InMemoryPreferences()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val store: PluginSettingsStore

    init {
        whenever(api.persistence().preferences()).thenReturn(prefs)
        store = AgentSettingsRepository(api).pluginSettings()
    }

    @Test
    fun anEmptyPreferencesNodeReadsThe101Defaults() {
        val settings = CliSettings(store)
        DEFAULTS_101.forEach { (id, expected) ->
            assertEquals(expected, settings.command(id), "$id default")
        }
        assertEquals(120, settings.timeoutSeconds(), "absent cli.timeoutSeconds reads as Defaults.CLI_PROCESS_TIMEOUT_SECONDS")
    }

    @Test
    fun withoutAStoreTheDefaultsAreUsed() {
        val settings = CliSettings(null)
        DEFAULTS_101.forEach { (id, expected) -> assertEquals(expected, settings.command(id), "$id default") }
        assertEquals(120, settings.timeoutSeconds())
    }

    @Test
    fun storedValuesAreReadUnchangedUnderTheir101Keys() {
        val stored =
            mapOf(
                "codex.cmd" to "codex exec --full-auto",
                "gemini.cmd" to "gemini --model 'gemini 2.5'",
                "opencode.cmd" to "opencode run",
                "claude.cmd" to "claude -p --verbose",
                "copilot.cmd" to "copilot --allow-all-tools",
                "ollama.cli.cmd" to "ollama run llama3.2",
            )
        prefs.strings.putAll(stored)
        val settings = CliSettings(store)
        assertEquals(stored.getValue("codex.cmd"), settings.command("codex-cli"))
        assertEquals(stored.getValue("gemini.cmd"), settings.command("gemini-cli"))
        assertEquals(stored.getValue("opencode.cmd"), settings.command("opencode-cli"))
        assertEquals(stored.getValue("claude.cmd"), settings.command("claude-cli"))
        assertEquals(stored.getValue("copilot.cmd"), settings.command("copilot-cli"))
        assertEquals(stored.getValue("ollama.cli.cmd"), settings.command("ollama"))
        assertEquals(stored.keys, CLI_IDS.map { CliSettings.keyFor(it) }.toSet(), "the 1.0.1 key names, unchanged")
        assertEquals(0, prefs.writes.size, "reading never writes a key")
    }

    @Test
    fun theLegacyGeminiDefaultReadsAsTheCurrentDefault() {
        prefs.strings["gemini.cmd"] = "gemini --output-format text --model gemini-2.5-flash"
        assertEquals(DEFAULTS_101.getValue("gemini-cli"), CliSettings(store).command("gemini-cli"))
        assertEquals(0, prefs.writes.size, "the plug-in normalizes on read and writes nothing")
    }

    @Test
    fun aBlankStoredCommandStaysBlankSoTheBackendCanReportIt() {
        prefs.strings["codex.cmd"] = "   "
        assertEquals("", CliSettings(store).command("codex-cli"))
    }

    @Test
    fun theTimeoutIsClampedToTheWatchdogRange() {
        mapOf(29 to 30, 30 to 30, 450 to 450, 3600 to 3600, 3601 to 3600, -5 to 30).forEach { (stored, expected) ->
            prefs.integers["cli.timeoutSeconds"] = stored
            assertEquals(expected, CliSettings(store).timeoutSeconds(), "stored $stored")
        }
    }

    @Test
    fun anUnknownIdHasNoKeyAndNoCommand() {
        assertNull(CliSettings.keyFor("lmstudio"))
        assertEquals("", CliSettings(store).command("lmstudio"))
    }

    @Test
    fun theOllamaHintParsesTheModelFromTheOllamaCliCommand() {
        val hint = OllamaCliModelHint()
        prefs.strings["ollama.cli.cmd"] = "ollama run llama3.2"
        assertEquals("llama3.2", hint.defaultModel("ollama", store))
        assertNull(hint.defaultModel("lmstudio", store), "the hint answers for ollama only")

        prefs.strings["ollama.cli.cmd"] = "ollama run --verbose"
        assertNull(hint.defaultModel("ollama", store), "a flag after run is not a model")

        prefs.strings["ollama.cli.cmd"] = " "
        assertNull(hint.defaultModel("ollama", store), "a blank command has no model")

        prefs.strings.remove("ollama.cli.cmd")
        assertEquals("llama3.1", hint.defaultModel("ollama", store), "the default command names llama3.1")
    }

    @Test
    fun theOllamaHintIsTheOneBackendModelHintOfTheFullBuild() {
        assertEquals(
            listOf(OllamaCliModelHint::class.java.name),
            Plugins.load(BackendModelHint::class.java).map { it.javaClass.name },
        )
    }

    @Test
    fun aBlankOllamaModelFallsBackToTheModelInTheOllamaCliCommand() {
        prefs.strings["ollama.cli.cmd"] = "ollama run qwen2.5-coder"
        val supervisor = AgentSupervisor(api, BackendRegistry(api), mock<AuditLogger>(), FullAiAccessPolicy())
        supervisor.pluginSettings = store
        supervisor.applySettings(TestSettings.baselineSettings("ollama").copy(ollamaModel = ""))
        assertEquals("qwen2.5-coder", ollamaLaunchConfig(supervisor).model)

        supervisor.applySettings(TestSettings.baselineSettings("ollama").copy(ollamaModel = "mistral"))
        assertEquals("mistral", ollamaLaunchConfig(supervisor).model, "an explicit model always wins")
    }

    private fun ollamaLaunchConfig(supervisor: AgentSupervisor): BackendLaunchConfig {
        val method =
            AgentSupervisor::class.java.getDeclaredMethod(
                "buildLaunchConfig",
                String::class.java,
                String::class.java,
                String::class.java,
            )
        method.isAccessible = true
        return method.invoke(supervisor, "ollama", "session-cli-settings-test", null) as BackendLaunchConfig
    }

    private companion object {
        val CLI_IDS = listOf("codex-cli", "gemini-cli", "opencode-cli", "claude-cli", "copilot-cli", "ollama")

        // The 1.0.1 AgentSettings defaults, verbatim.
        val DEFAULTS_101 =
            linkedMapOf(
                "codex-cli" to "codex chat",
                "gemini-cli" to "gemini --output-format text --model gemini-2.5-flash --yolo",
                "opencode-cli" to "opencode",
                "claude-cli" to "claude",
                "copilot-cli" to "copilot",
                "ollama" to "ollama run llama3.1",
            )
    }
}
