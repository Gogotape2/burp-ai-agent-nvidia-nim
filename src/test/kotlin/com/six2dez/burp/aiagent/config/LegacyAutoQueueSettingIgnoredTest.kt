package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever

/**
 * Phase 32 SC2 (T-32-04) — the 1.0.1 core auto-queue preference is never read, written or deleted, and
 * no core field, key constant or settings row for it exists, so an upgrade cannot switch target traffic
 * on behind the user's back.
 *
 * Phase 29 D-08 deliberately leaves the stored value in place so a downgrade to 1.0.1 still reads it;
 * the core never touches it. The full build's opt-in auto-queue plug-in has its own key and its own
 * row, so the label check walks `src/main` only.
 */
class LegacyAutoQueueSettingIgnoredTest {
    @Test
    fun loadNeverReadsWritesOrDeletesTheLegacyKey() {
        val prefs = spy(InMemoryPreferences())
        prefs.booleans[LEGACY_KEY] = true
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)

        AgentSettingsRepository(api).load()

        val invocations = Mockito.mockingDetails(prefs).invocations
        assertTrue(invocations.isNotEmpty(), "Anti-vacuity: load() must have read the preferences")
        val touching =
            invocations
                .filter { invocation -> invocation.arguments.any { it == LEGACY_KEY } }
                .map { it.method.name }
        assertEquals(emptyList<String>(), touching, "load() passed the legacy key to the preferences")
        assertEquals(0, prefs.writeCount(LEGACY_KEY), "the legacy key is never written")
        assertEquals(0, prefs.deleteCount(LEGACY_KEY), "the legacy key is never deleted (D-08)")
        assertEquals(true, prefs.booleans[LEGACY_KEY], "the stored value stays for a downgrade")
    }

    @Test
    fun agentSettingsDeclaresNoAutoQueueField() {
        val autoQueueFields =
            AgentSettings::class.java.declaredFields
                .map { it.name }
                .filter { name -> FORBIDDEN_FIELD_FRAGMENTS.any { name.contains(it, ignoreCase = true) } }
        assertEquals(emptyList<String>(), autoQueueFields, "AgentSettings declares an auto-queue field")
    }

    @Test
    fun noProductionSourceNamesTheLegacyFieldConstantOrKey() {
        val files = SourceRoots.kotlinFiles()
        assertTrue(files.size >= MIN_EXPECTED_MAIN_FILES, "walked ${files.size} production files, below the floor of $MIN_EXPECTED_MAIN_FILES")
        val hits =
            files.flatMap { file ->
                val text = file.readText(Charsets.UTF_8)
                LEGACY_TOKENS.filter { it in text }.map { "${SourceRoots.relativePath(file)}: $it" }
            }
        assertEquals(emptyList<String>(), hits, "a production source names the 1.0.1 auto-queue setting")
    }

    @Test
    fun theCoreHasNoAutoQueueRow() {
        val mainFiles =
            SourceRoots
                .root(SourceRoots.MAIN)
                .walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .toList()
        assertTrue(mainFiles.size >= MIN_EXPECTED_MAIN_FILES, "walked ${mainFiles.size} src/main files, below the floor of $MIN_EXPECTED_MAIN_FILES")
        val hits =
            mainFiles
                .filter { OLD_ROW_LABEL in it.readText(Charsets.UTF_8) }
                .map { SourceRoots.relativePath(it) }
        assertEquals(emptyList<String>(), hits, "a core file still carries the 1.0.1 auto-queue row")
    }

    private companion object {
        const val LEGACY_KEY = "active.ai.auto.passive"
        const val LEGACY_FIELD = "activeAiAutoFromPassive"
        const val LEGACY_CONSTANT = "KEY_ACTIVE_AI_AUTO_PASSIVE"
        const val OLD_ROW_LABEL = "Auto-queue findings"
        const val MIN_EXPECTED_MAIN_FILES = 150
        val LEGACY_TOKENS = listOf(LEGACY_FIELD, LEGACY_CONSTANT, LEGACY_KEY)
        val FORBIDDEN_FIELD_FRAGMENTS = listOf("autofrompassive", "autoqueue")
    }
}
