package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 31 / D-05, D-06 (GATE-02) — the passive and active AI scanner switches are session-only in
 * both builds: they start OFF at every load whatever Burp's preferences say, a session change is seen
 * by every reader of the same repository, and the two stored keys are never written or deleted, so a
 * 1.0.1 downgrade still reads them.
 */
class ScannerSessionStateTest {
    /** (a) D-05 — saved ON in the preferences, loaded OFF; the stored values stay exactly as they were. */
    @Test
    fun scannersSavedOnInThePreferencesLoadOff() {
        val prefs = preferencesWithBothScannersSavedOn()

        val loaded = AgentSettingsRepository(apiWith(prefs)).load()

        assertFalse(loaded.passiveAiEnabled, "D-05: the passive scanner must start OFF at load.")
        assertFalse(loaded.activeAiEnabled, "D-05: the active scanner must start OFF at load.")
        assertEquals(true, prefs.booleans[PASSIVE_KEY], "D-06: the stored passive value must stay untouched.")
        assertEquals(true, prefs.booleans[ACTIVE_KEY], "D-06: the stored active value must stay untouched.")
        assertNoScannerKeyWriteOrDelete(prefs)
    }

    /** (b) D-06 — a session toggle is seen by the same repository and never reaches the preferences. */
    @Test
    fun aSessionToggleIsSeenByTheSameRepositoryAndNeverWritten() {
        val prefs = InMemoryPreferences()
        val api = apiWith(prefs)
        val repo = AgentSettingsRepository(api)

        repo.update { it.copy(passiveAiEnabled = true, activeAiEnabled = true) }

        assertTrue(repo.load().passiveAiEnabled, "D-06: the same repository must report the session passive value.")
        assertTrue(repo.load().activeAiEnabled, "D-06: the same repository must report the session active value.")
        val fresh = AgentSettingsRepository(api).load()
        assertFalse(fresh.passiveAiEnabled, "D-06: a new load must start the passive scanner OFF again.")
        assertFalse(fresh.activeAiEnabled, "D-06: a new load must start the active scanner OFF again.")
        assertTrue(
            prefs.writes.isNotEmpty(),
            "Anti-vacuity: the save must have written the other settings.",
        )
        assertNoScannerKeyWriteOrDelete(prefs)
    }

    /**
     * (c) D-06 / Pitfall 9 — a save whose preference write fails evicts the cache but keeps the session
     * scanner values, so the next load() agrees with the scanner objects the user switched on.
     */
    @Test
    fun aFailedSaveKeepsTheSessionScannerValues() {
        val inner = InMemoryPreferences()
        val prefs = FailingSchemaVersionPreferences(inner)
        val repo = AgentSettingsRepository(apiWith(prefs))
        repo.load()

        prefs.failSchemaVersionWrite = true
        assertThrows<IllegalStateException> {
            repo.save(repo.load().copy(passiveAiEnabled = true, activeAiEnabled = true))
        }
        prefs.failSchemaVersionWrite = false

        val afterEviction = repo.load()
        assertTrue(
            afterEviction.passiveAiEnabled,
            "D-06: after a failed save evicts the cache, load() must still report the session passive value.",
        )
        assertTrue(
            afterEviction.activeAiEnabled,
            "D-06: after a failed save evicts the cache, load() must still report the session active value.",
        )
        assertNoScannerKeyWriteOrDelete(inner)
    }

    /**
     * (d) D-05 — the scanner objects, switched the way App.initialize switches them from the loaded
     * snapshot, stay disabled after a load over preferences that say ON.
     */
    @Test
    fun scannersSwitchedFromTheLoadedSnapshotStayDisabled() {
        val prefs = preferencesWithBothScannersSavedOn()
        val api = apiWith(prefs)
        val repo = AgentSettingsRepository(api)
        val supervisor = mock<AgentSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val audit = mock<AuditLogger>()
        val passive = PassiveAiScanner(api, supervisor, audit) { repo.load() }
        val active = ActiveAiScanner(api, supervisor, audit) { repo.load() }
        try {
            // App.initialize, verbatim in shape.
            val settings = repo.load()
            passive.setEnabled(settings.passiveAiEnabled)
            active.setEnabled(settings.activeAiEnabled)

            assertFalse(passive.isEnabled(), "D-05: the passive scanner must be OFF after load.")
            assertFalse(active.isEnabled(), "D-05: the active scanner must be OFF after load.")
        } finally {
            passive.shutdown()
            active.shutdown()
        }
    }

    private fun preferencesWithBothScannersSavedOn(): InMemoryPreferences {
        val prefs = InMemoryPreferences()
        // What a 1.0.1 install left behind. Seeded straight into the map so no write is recorded.
        prefs.booleans[PASSIVE_KEY] = true
        prefs.booleans[ACTIVE_KEY] = true
        return prefs
    }

    private fun assertNoScannerKeyWriteOrDelete(prefs: InMemoryPreferences) {
        assertEquals(0, prefs.writeCount(PASSIVE_KEY), "D-06: passive.ai.enabled must never be written.")
        assertEquals(0, prefs.writeCount(ACTIVE_KEY), "D-06: active.ai.enabled must never be written.")
        assertEquals(0, prefs.deleteCount(PASSIVE_KEY), "D-06: passive.ai.enabled must never be deleted.")
        assertEquals(0, prefs.deleteCount(ACTIVE_KEY), "D-06: active.ai.enabled must never be deleted.")
    }

    private fun apiWith(preferences: Preferences): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    /** Throws on the schema-version write, the last write save() makes, once armed. */
    private class FailingSchemaVersionPreferences(
        private val inner: InMemoryPreferences,
    ) : Preferences by inner {
        @Volatile var failSchemaVersionWrite = false

        override fun setInteger(
            key: String,
            value: Int,
        ) {
            check(!(failSchemaVersionWrite && key == SCHEMA_VERSION_KEY)) { "simulated preference write failure" }
            inner.setInteger(key, value)
        }
    }

    private companion object {
        const val PASSIVE_KEY = "passive.ai.enabled"
        const val ACTIVE_KEY = "active.ai.enabled"
        const val SCHEMA_VERSION_KEY = "settings.schema.version"
    }
}
