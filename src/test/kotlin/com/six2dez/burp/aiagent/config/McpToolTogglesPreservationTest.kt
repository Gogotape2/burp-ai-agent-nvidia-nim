package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 plan 29-11 (RESEARCH Pitfall 13, D-08, T-29-21): a settings save in the store build must
 * not destroy the full build's per-tool settings.
 *
 * `mcp.tools.toggles` and `mcp.unsafe.tools` are single keys holding a map / set of tool ids, and both
 * flavors share the same preferences node. The store UI builds them from the store catalog only (the
 * 8 native tools), so before this fix a store save dropped every generic entry the full build had
 * stored. The save now carries stored entries whose id is not in [McpToolCatalog.all] over unchanged
 * and takes the new value for catalog ids.
 *
 * Runs on the store classpath: the test first proves the generic ids it uses are not in the catalog,
 * so it can never pass vacuously on a classpath that has them.
 */
class McpToolTogglesPreservationTest {
    @Test
    fun storeSaveCarriesOverStoredTogglesAndUnsafeIdsTheStoreCatalogDoesNotHave() {
        assertStoreCatalogLacks(FULL_ONLY_TOGGLE_ID, FULL_ONLY_UNSAFE_ID)
        val (repo, prefs) = newRepository()
        prefs.setString(TOGGLES_KEY, McpSettings.serializeToolToggles(mapOf(FULL_ONLY_TOGGLE_ID to false, "status" to true)))
        prefs.setString(UNSAFE_KEY, McpSettings.serializeUnsafeToolSet(setOf(FULL_ONLY_UNSAFE_ID)))

        repo.save(settingsWith(repo, toggles = mapOf("status" to false), unsafe = emptySet()))

        assertEquals(
            mapOf(FULL_ONLY_TOGGLE_ID to false, "status" to false),
            McpSettings.parseToolToggles(prefs.getString(TOGGLES_KEY)),
            "the full-only toggle must survive the store save; the catalog toggle takes the new value",
        )
        assertEquals(
            setOf(FULL_ONLY_UNSAFE_ID),
            McpSettings.parseUnsafeToolSet(prefs.getString(UNSAFE_KEY)),
            "the full-only unsafe allowlist entry must survive a store save of an empty allowlist",
        )
    }

    @Test
    fun storeSaveTakesTheNewValueForCatalogIdsItTurnsOffOrRemoves() {
        assertStoreCatalogLacks(FULL_ONLY_TOGGLE_ID, FULL_ONLY_UNSAFE_ID)
        val (repo, prefs) = newRepository()
        prefs.setString(
            TOGGLES_KEY,
            McpSettings.serializeToolToggles(mapOf("status" to true, "ai_analyze" to true, FULL_ONLY_TOGGLE_ID to true)),
        )
        prefs.setString(UNSAFE_KEY, McpSettings.serializeUnsafeToolSet(setOf("issue_create", "ai_analyze", FULL_ONLY_UNSAFE_ID)))

        repo.save(
            settingsWith(
                repo,
                toggles = mapOf("status" to true, "ai_analyze" to false),
                unsafe = setOf("ai_analyze"),
            ),
        )

        val toggles = McpSettings.parseToolToggles(prefs.getString(TOGGLES_KEY))
        assertEquals(false, toggles["ai_analyze"], "a catalog id toggled off must be stored off")
        assertEquals(true, toggles["status"])
        assertEquals(true, toggles[FULL_ONLY_TOGGLE_ID], "the full-only toggle is carried over unchanged")
        val unsafe = McpSettings.parseUnsafeToolSet(prefs.getString(UNSAFE_KEY))
        assertFalse("issue_create" in unsafe, "a catalog id removed from the allowlist must be removed from storage")
        assertEquals(setOf("ai_analyze", FULL_ONLY_UNSAFE_ID), unsafe)
    }

    @Test
    fun storeSaveRoundTripsThroughLoadWithTheCarriedOverEntries() {
        val (repo, prefs) = newRepository()
        prefs.setString(TOGGLES_KEY, McpSettings.serializeToolToggles(mapOf(FULL_ONLY_TOGGLE_ID to false)))
        prefs.setString(UNSAFE_KEY, McpSettings.serializeUnsafeToolSet(setOf(FULL_ONLY_UNSAFE_ID)))

        repo.save(settingsWith(repo, toggles = mapOf("status" to false), unsafe = emptySet()))
        val loaded = AgentSettingsRepository(apiFor(prefs)).load().mcpSettings

        assertEquals(mapOf(FULL_ONLY_TOGGLE_ID to false, "status" to false), loaded.toolToggles)
        assertEquals(setOf(FULL_ONLY_UNSAFE_ID), loaded.enabledUnsafeTools)
    }

    private fun assertStoreCatalogLacks(vararg ids: String) {
        val catalogIds = McpToolCatalog.all().map { it.id }.toSet()
        ids.forEach { id ->
            assertFalse(id in catalogIds, "precondition: '$id' must not be in the store catalog, or this test is vacuous")
        }
    }

    private fun settingsWith(
        repo: AgentSettingsRepository,
        toggles: Map<String, Boolean>,
        unsafe: Set<String>,
    ): AgentSettings {
        val defaults = repo.defaultSettings()
        return defaults.copy(mcpSettings = defaults.mcpSettings.copy(toolToggles = toggles, enabledUnsafeTools = unsafe))
    }

    private fun newRepository(prefs: InMemoryPreferences = InMemoryPreferences()): Pair<AgentSettingsRepository, InMemoryPreferences> =
        AgentSettingsRepository(apiFor(prefs)) to prefs

    private fun apiFor(prefs: InMemoryPreferences): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return api
    }

    private companion object {
        const val TOGGLES_KEY = "mcp.tools.toggles"
        const val UNSAFE_KEY = "mcp.unsafe.tools"

        /** Generic tool ids from the full build's catalog (GenericRequestTools / GenericScannerTools). */
        const val FULL_ONLY_TOGGLE_ID = "http1_request"
        const val FULL_ONLY_UNSAFE_ID = "intruder"
    }
}
