package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 / D-06, user decision 2026-10-09 — in the store build Ollama's model comes from the Model
 * field, else llama3.1. The store build has no Ollama CLI command and no BackendModelHint provider, so a
 * full install's `ollama.cli.cmd` left in the shared preferences node is neither read nor written.
 */
class OllamaDefaultModelTest {
    private val prefs = InMemoryPreferences()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    init {
        whenever(api.persistence().preferences()).thenReturn(prefs)
    }

    @Test
    fun aBlankOllamaModelIsLlama31InTheStoreBuildWhateverTheCliKeySays() {
        prefs.strings["ollama.cli.cmd"] = "ollama run qwen2.5-coder"
        val supervisor = AgentSupervisor(api, BackendRegistry(api), mock<AuditLogger>(), StoreAiAccessPolicy())
        supervisor.pluginSettings = AgentSettingsRepository(api).pluginSettings()

        supervisor.applySettings(TestSettings.baselineSettings("ollama").copy(ollamaModel = ""))
        assertEquals("llama3.1", ollamaLaunchConfig(supervisor).model)

        supervisor.applySettings(TestSettings.baselineSettings("ollama").copy(ollamaModel = "mistral"))
        assertEquals("mistral", ollamaLaunchConfig(supervisor).model)

        assertEquals(0, prefs.writeCount("ollama.cli.cmd"), "the store build never writes the full-only key")
        assertEquals("ollama run qwen2.5-coder", prefs.strings["ollama.cli.cmd"])
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
        return method.invoke(supervisor, "ollama", "session-ollama-default-model", null) as BackendLaunchConfig
    }
}
