package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.InvocationTargetException
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

/**
 * Phase 31 / D-13 — on the store test classpath the loaded catalog has no `unsafeOnly` tool, so the MCP
 * Unsafe switch is visible but disabled, explains itself with [NO_UNSAFE_TOOLS_NOTE], and never rewrites
 * the saved value: a Settings Save writes back exactly what was loaded. Fixtures are copied from
 * AuditVerboseSettingTest.
 */
class McpUnsafeSwitchTest {
    @TempDir
    lateinit var root: Path

    private val panels = CopyOnWriteArrayList<SettingsPanel>()

    @AfterEach
    fun releaseFixtures() {
        OffEdtDispatch.registerSettledObserver(null)
        // The Save body installs custom patterns into the process-wide Redaction singleton.
        Redaction.setCustomPatterns(emptyList())
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    @Test
    fun theStoreCatalogHasNoUnsafeTools() {
        assertTrue(McpToolCatalog.available().isNotEmpty(), "Anti-vacuity: the store catalog loads its native tools.")
        assertFalse(McpToolCatalog.hasUnsafeTools(), "The store build ships no unsafeOnly tool.")
        assertTrue(McpToolCatalog.unsafeToolIds().isEmpty(), "hasUnsafeTools agrees with unsafeToolIds.")
    }

    @Test
    fun aCarriedOverUnsafeTrueShowsTheSwitchSelectedButDisabledWithItsNote() {
        val store = PrefsStore().apply { booleans[KEY_MCP_UNSAFE] = true }
        val repo = AgentSettingsRepository(newApi(store))
        assertTrue(repo.load().mcpSettings.unsafeEnabled, "Anti-vacuity: the seeded value loads as true.")
        val panel = newPanel(repo)
        onEdt {
            assertTrue(panel.mcpUnsafe.isVisible, "The switch stays visible.")
            assertFalse(panel.mcpUnsafe.isEnabled, "The switch is disabled when the catalog has no unsafe tool.")
            assertTrue(panel.mcpUnsafe.isSelected, "The carried-over value is shown, not rewritten.")
            assertEquals(NO_UNSAFE_TOOLS_NOTE, panel.mcpUnsafe.toolTipText, "The tooltip explains why.")
            assertEquals("No unsafe tools in this build", NO_UNSAFE_TOOLS_NOTE)
            assertTrue(panel.mcpUnsafeNote.isVisible, "The note is shown beside the switch.")
            assertEquals(NO_UNSAFE_TOOLS_NOTE, panel.mcpUnsafeNote.text)
            assertNotNull(panel.mcpUnsafe.parent, "Anti-vacuity: the switch is placed in the MCP section.")
            assertSame(panel.mcpUnsafe.parent, panel.mcpUnsafeNote.parent, "The note shares the switch's cell.")
            assertTrue(panel.currentSettings().mcpSettings.unsafeEnabled, "The on-screen settings keep true.")
        }
    }

    @Test
    fun aSaveOverACarriedOverTrueWritesTrueBackUnchanged() {
        assertSaveKeeps(saved = true)
    }

    @Test
    fun aSaveOverASavedFalseKeepsFalse() {
        assertSaveKeeps(saved = false)
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private fun assertSaveKeeps(saved: Boolean) {
        val store = PrefsStore().apply { booleans[KEY_MCP_UNSAFE] = saved }
        val api = newApi(store)
        val repo = AgentSettingsRepository(api)
        val panel = newPanel(repo)
        onEdt {
            assertFalse(panel.mcpUnsafe.isEnabled, "Anti-vacuity: the switch is disabled on the store classpath.")
            assertEquals(saved, panel.mcpUnsafe.isSelected, "The switch shows the saved value.")
        }
        store.writes.clear()

        saveAndSettle { panel.saveSettings() }

        assertTrue(store.writes.contains(KEY_MCP_UNSAFE), "Anti-vacuity: the Save wrote the unsafe key.")
        assertEquals(saved, store.booleans[KEY_MCP_UNSAFE], "The Save wrote the loaded value back unchanged.")
        assertEquals(saved, repo.load().mcpSettings.unsafeEnabled, "The repository snapshot keeps the value.")
        assertEquals(saved, AgentSettingsRepository(api).load().mcpSettings.unsafeEnabled, "A fresh load keeps it.")
        onEdt {
            assertEquals(saved, panel.mcpUnsafe.isSelected, "The sync after Save keeps the selection.")
            assertFalse(panel.mcpUnsafe.isEnabled, "The switch stays disabled after the Save.")
        }
    }

    /** Runs [block] on the EDT and rethrows its own failure rather than the invocation wrapper. */
    private fun onEdt(block: () -> Unit) {
        try {
            SwingUtilities.invokeAndWait(block)
        } catch (wrapped: InvocationTargetException) {
            throw wrapped.cause ?: wrapped
        }
    }

    /** Runs [dispatch] on the EDT, waits for that save to settle, then drains the EDT once. */
    private fun saveAndSettle(dispatch: () -> Unit) {
        val settled = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { settled.countDown() }
        onEdt(dispatch)
        assertTimeoutPreemptively(Duration.ofSeconds(FAILSAFE_SECONDS)) {
            assertTrue(settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "The save never settled.")
        }
        onEdt { }
    }

    private class PrefsStore {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val writes = CopyOnWriteArrayList<String>()
    }

    private fun newApi(store: PrefsStore): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = inMemoryPreferences(store)
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        return api
    }

    private fun newPanel(repo: AgentSettingsRepository): SettingsPanel {
        val api = newApi(PrefsStore())
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = repo,
                backends = backends,
                supervisor = mock<AgentSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                audit = AuditLogger(newApi(PrefsStore()), root.resolve("audit-home").toFile()),
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                buildIdentity = "Custom AI Agent test (test build)",
            )
        panels.add(panel)
        return panel
    }

    private fun inMemoryPreferences(store: PrefsStore): Preferences {
        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { store.strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            store.strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { store.booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            store.writes += it.getArgument<String>(0)
            store.booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { store.integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            store.integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
    }

    private companion object {
        const val FAILSAFE_SECONDS = 20L

        /** The preference key AgentSettingsRepository stores McpSettings.unsafeEnabled under. */
        const val KEY_MCP_UNSAFE = "mcp.unsafe.enabled"
    }
}
