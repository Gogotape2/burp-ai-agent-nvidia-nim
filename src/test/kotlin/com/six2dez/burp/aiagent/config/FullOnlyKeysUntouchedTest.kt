package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 / D-08, threat T-29-26 — both flavors share one Burp preferences node, and the store build
 * must leave a full install's CLI configuration exactly as it found it, so switching back to the full
 * JAR restores it. The store-classpath repository never reads, writes or deletes the full-only CLI
 * keys: they now belong to the full build's CLI plug-in under their 1.0.1 names (D-11).
 */
class FullOnlyKeysUntouchedTest {
    private val prefs = InMemoryPreferences()
    private val repo: AgentSettingsRepository

    init {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        prefs.strings.putAll(SEEDED_STRINGS)
        prefs.integers[KEY_CLI_TIMEOUT] = SEEDED_TIMEOUT
        repo = AgentSettingsRepository(api)
    }

    @Test
    fun loadSaveUpdateAndDefaultsLeaveEveryFullOnlyKeyAsSeeded() {
        val loaded = repo.load()
        repo.save(loaded)
        repo.update { it.copy(determinismMode = !it.determinismMode) }
        repo.save(repo.defaultSettings())

        assertSeededAndUntouched()
    }

    @Test
    fun aFreshInstallSaveCreatesNoFullOnlyKey() {
        val fresh = InMemoryPreferences()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(fresh)
        val freshRepo = AgentSettingsRepository(api)
        freshRepo.save(freshRepo.load())
        freshRepo.save(freshRepo.defaultSettings())

        FULL_ONLY_KEYS.forEach { key ->
            assertEquals(0, fresh.writeCount(key), "$key must not be written by the store build")
            assertEquals(null, fresh.strings[key] ?: fresh.integers[key], "$key must not exist after a store save")
        }
    }

    private fun assertSeededAndUntouched() {
        SEEDED_STRINGS.forEach { (key, value) ->
            assertEquals(value, prefs.strings[key], "$key keeps its seeded value (the legacy Gemini default included)")
        }
        assertEquals(SEEDED_TIMEOUT, prefs.integers[KEY_CLI_TIMEOUT], "$KEY_CLI_TIMEOUT keeps its seeded value, unclamped")
        FULL_ONLY_KEYS.forEach { key ->
            assertEquals(0, prefs.writeCount(key), "$key: zero writes from the store repository")
            assertEquals(0, prefs.deleteCount(key), "$key: zero deletes from the store repository")
        }
    }

    private companion object {
        const val KEY_CLI_TIMEOUT = "cli.timeoutSeconds"

        // A value outside 30..3600, so a store-side clamp-and-save would show as a changed value.
        const val SEEDED_TIMEOUT = 5000

        val SEEDED_STRINGS =
            mapOf(
                "codex.cmd" to "codex exec --full-auto",
                // The 1.0.1 legacy default the old core migration rewrote; the store build must not.
                "gemini.cmd" to "gemini --output-format text --model gemini-2.5-flash",
                "opencode.cmd" to "opencode run",
                "claude.cmd" to "claude -p",
                "copilot.cmd" to "copilot --allow-all-tools",
                "ollama.cli.cmd" to "ollama run llama3.2",
            )

        val FULL_ONLY_KEYS = SEEDED_STRINGS.keys + KEY_CLI_TIMEOUT
    }
}
