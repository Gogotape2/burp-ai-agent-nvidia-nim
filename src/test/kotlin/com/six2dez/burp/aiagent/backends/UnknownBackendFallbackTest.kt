package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.ChatPanelTestHarness
import com.six2dez.burp.aiagent.ui.OffEdtDispatch
import com.six2dez.burp.aiagent.ui.SettingsPanel
import com.six2dez.burp.aiagent.ui.applySettingsToUi
import com.six2dez.burp.aiagent.ui.components.SubtleNotice
import com.six2dez.burp.aiagent.ui.currentSettings
import com.six2dez.burp.aiagent.ui.saveSettings
import com.six2dez.burp.aiagent.ui.setPreferredBackend
import com.six2dez.burp.aiagent.ui.shutdown
import com.six2dez.burp.aiagent.ui.unavailableBackendId
import com.six2dez.burp.aiagent.ui.unavailableBackendNoticeHtml
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.JTextPane
import javax.swing.SwingUtilities

/**
 * Phase 29 / D-08 on the store classpath: a saved backend id the build does not register (a CLI id a
 * full install left behind) falls back to burp-ai without failing, without a blank picker, and without
 * losing the user's stored choice. Also the UI-SPEC contract of the S5/S8 notice (PC-1..PC-3) and the
 * S24 substitution log line (PC-4).
 */
class UnknownBackendFallbackTest {
    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val settled = CopyOnWriteArrayList<String>()

    @BeforeEach
    fun installObserver() {
        settled.clear()
        OffEdtDispatch.registerSettledObserver { settled.add(it) }
    }

    @AfterEach
    fun release() {
        OffEdtDispatch.registerSettledObserver(null)
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    @Test
    fun registryResolvesAnUnregisteredIdToBurpAi() {
        val registry = BackendRegistry(Fixture("codex-cli").api)

        assertEquals("burp-ai", BackendRegistry.DEFAULT_BACKEND_ID)
        assertFalse(registry.isRegistered("codex-cli"))
        assertEquals("burp-ai", registry.resolve("codex-cli"))
        assertTrue(registry.isRegistered("ollama"))
        assertEquals("ollama", registry.resolve("ollama"))
    }

    @Test
    fun theDefaultBackendIdIsTheRepositoryDefault() {
        assertEquals(BackendRegistry.DEFAULT_BACKEND_ID, AgentSettingsRepository(Fixture("ollama").api).defaultSettings().preferredBackendId)
    }

    @Test
    fun storeLoadOverACliSelectionPicksBurpAiShowsTheNoticeAndWritesNothing() {
        val fixture = Fixture("codex-cli")
        val panel = fixture.panel()

        assertEquals("burp-ai", panel.preferredBackend.selectedItem, "B1: the picker shows burp-ai, never blank")
        assertTrue(panel.unavailableBackendNotice.isVisible, "B1: the S8 notice is shown")
        assertTrue(panel.unavailableBackendNoticeRow.isVisible, "B1: the notice row is shown with it")
        assertTrue(renderedText(panel.unavailableBackendNotice).contains("'codex-cli'"), renderedText(panel.unavailableBackendNotice))
        assertEquals(0, fixture.preferredBackendWrites(), "P-1: loading must not write backend.preferred")
        assertEquals("codex-cli", fixture.storedBackend())
    }

    @Test
    fun savingUnrelatedSettingsKeepsTheStoredCliIdAndAPickReplacesIt() {
        val fixture = Fixture("codex-cli")
        val panel = fixture.panel()

        assertEquals("codex-cli", panel.currentSettings().preferredBackendId)
        save(panel)
        assertEquals("codex-cli", fixture.storedBackend(), "a Save of unrelated settings writes the saved id back")
        assertTrue(panel.unavailableBackendNotice.isVisible, "the notice stays while the substitution stands")

        SwingUtilities.invokeAndWait { panel.setPreferredBackend("ollama") }
        assertFalse(panel.unavailableBackendNotice.isVisible, "a user pick hides the notice")
        save(panel)
        assertEquals("ollama", fixture.storedBackend(), "the explicit pick replaces the stored id")
    }

    @Test
    fun rePickingBurpAiReplacesTheStoredIdAndHidesTheNotice() {
        val fixture = Fixture("codex-cli")
        val panel = fixture.panel()

        SwingUtilities.invokeAndWait { panel.setPreferredBackend("burp-ai") }

        assertFalse(panel.unavailableBackendNotice.isVisible)
        assertFalse(panel.unavailableBackendNoticeRow.isVisible, "a hidden notice takes no space")
        assertEquals("burp-ai", panel.currentSettings().preferredBackendId)
    }

    @Test
    fun registeredSavedIdShowsNoNotice() {
        val panel = Fixture("ollama").panel()

        assertEquals("ollama", panel.preferredBackend.selectedItem)
        assertFalse(panel.unavailableBackendNotice.isVisible, "B0: no notice")
        assertFalse(panel.unavailableBackendNoticeRow.isVisible, "B0: the row takes no space")
    }

    @Test
    fun noticeFormatterIsC_N1WithTheIdEscapedAndCut() {
        // UI-SPEC PC-1 / P-4.
        assertEquals(
            "Saved backend 'codex-cli' is not available in this build; using Burp AI. Pick another backend to replace it.",
            unavailableBackendNoticeHtml("codex-cli"),
        )
        val escaped = unavailableBackendNoticeHtml("<b>x</b>")
        assertTrue(escaped.contains("'&lt;b&gt;x&lt;/b&gt;'"), escaped)
        assertFalse(escaped.contains("<b>"), escaped)
        assertTrue(unavailableBackendNoticeHtml("a\"b'c&d").contains("a&quot;b&#39;c&amp;d"))

        val long = "x".repeat(64) + "y".repeat(136)
        val cut = unavailableBackendNoticeHtml(long)
        assertTrue(cut.contains("'${"x".repeat(64)}…'"), cut)
        assertFalse(cut.contains("y"), "only the first 64 characters are kept")
    }

    @Test
    fun noticeRendersAnHtmlIdLiterallyAndALongIdCut() {
        val html = Fixture("<b>x</b>").panel()
        assertTrue(renderedText(html.unavailableBackendNotice).contains("Saved backend '<b>x</b>' is not available"))

        val long = "z".repeat(200)
        val cut = Fixture(long).panel()
        val text = renderedText(cut.unavailableBackendNotice)
        assertTrue(text.contains("'${"z".repeat(64)}…'"), text)
        assertFalse(text.contains("z".repeat(65)), text)
    }

    @Test
    fun s8NoticeIsTheFirstComponentOfTheAiBackendBody() {
        // UI-SPEC PC-2: first element of the AI Backend section body, above the Agent profile grid.
        val panel = Fixture("codex-cli").panel()
        val body = panel.aiBackendSectionBody

        assertSame(panel.unavailableBackendNoticeRow, body.getComponent(0))
        assertSame(panel.unavailableBackendNotice, panel.unavailableBackendNoticeRow.getComponent(0))
        val gap = (panel.unavailableBackendNoticeRow.border as javax.swing.border.EmptyBorder).borderInsets
        assertEquals(java.awt.Insets(0, 0, com.six2dez.burp.aiagent.ui.design.DesignTokens.Spacing.sm, 0), gap)
    }

    @Test
    fun persistingBurpAiAndApplyingHidesTheNotice() {
        // UI-SPEC PC-3: what a header pick of burp-ai writes, then the settings apply.
        val fixture = Fixture("codex-cli")
        val panel = fixture.panel()
        assertTrue(panel.unavailableBackendNotice.isVisible)

        fixture.strings[PREFERRED_KEY] = "burp-ai"
        val applied = AgentSettingsRepository(fixture.api).load()
        SwingUtilities.invokeAndWait { panel.applySettingsToUi(applied, notifyHosts = false) }

        assertFalse(panel.unavailableBackendNotice.isVisible)
        assertNull(unavailableBackendId(applied.preferredBackendId, fixture.registry))
        assertEquals("codex-cli", unavailableBackendId("codex-cli", fixture.registry))
    }

    @Test
    fun supervisorLogsOneSubstitutionLinePerUnknownId() {
        // UI-SPEC PC-4 / C-N9. The store policy refuses every send here (Use AI is off in the mock),
        // which is after the substitution, so no backend is launched.
        val fixture = Fixture("codex-cli")
        val supervisor = AgentSupervisor(fixture.api, fixture.registry, mock<AuditLogger>(), StoreAiAccessPolicy())
        repeat(2) { sendTo(supervisor, "codex-cli") }
        sendTo(supervisor, "gemini-cli")
        sendTo(supervisor, "ollama")

        val lines = fixture.output.filter { it.contains("is not registered in this build") }
        assertEquals(
            listOf(
                "[AgentSupervisor] Saved backend 'codex-cli' is not registered in this build; using burp-ai.",
                "[AgentSupervisor] Saved backend 'gemini-cli' is not registered in this build; using burp-ai.",
            ),
            lines,
        )
    }

    /**
     * Phase 31 / D-14b (Phase 29 D-08, T-31-23): a CLI id carried over from a full install starts no
     * process in the store build. With Use AI on, the start resolves to burp-ai and runs it, the
     * registry has no such backend, the store classpath has no CLI backend class, and the substitution
     * line is logged once however often the id is started.
     */
    @Test
    fun storeStartOverACarriedOverCliIdRunsBurpAiAndStartsNoProcess() {
        val fixture = Fixture("codex-cli")
        whenever(fixture.api.ai().isEnabled()).thenReturn(true)
        // The Burp AI connection builds its PromptOptions through Montoya's static factory, which is
        // null outside Burp; a mock factory stands in, saved and restored as in ChatPanelToolGateTest.
        val savedFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        val supervisor = AgentSupervisor(fixture.api, fixture.registry, mock<AuditLogger>(), StoreAiAccessPolicy())
        try {
            assertTrue(supervisor.startOrAttach("codex-cli"), "the start succeeds on the substitute: ${supervisor.lastStartError()}")
            assertTrue(supervisor.startOrAttach("codex-cli"), "a second start attaches to the running substitute")

            assertEquals("burp-ai", supervisor.status().backendId, "burp-ai runs, not the saved CLI id")
            assertNull(fixture.registry.get("codex-cli"), "the store registry has no CLI backend")
            assertThrows<ClassNotFoundException> { Class.forName("com.six2dez.burp.aiagent.backends.cli.CliBackend") }
            assertEquals(
                listOf("[AgentSupervisor] Saved backend 'codex-cli' is not registered in this build; using burp-ai."),
                fixture.output.filter { it.contains("is not registered in this build") },
                "one substitution line",
            )
            assertFalse(fixture.output.any { it.startsWith("Launching backend codex-cli") }, "no CLI launch: ${fixture.output}")
        } finally {
            supervisor.stop()
            ObjectFactoryLocator.FACTORY = savedFactory
        }
    }

    private fun sendTo(
        supervisor: AgentSupervisor,
        backendId: String,
    ) {
        supervisor.sendChat(
            chatSessionId = "chat-1",
            backendId = backendId,
            text = "hi",
            contextJson = null,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            onChunk = {},
            onComplete = {},
        )
    }

    private fun save(panel: SettingsPanel) {
        val before = settled.size
        SwingUtilities.invokeAndWait { panel.saveSettings() }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25)
        while (settled.size == before && System.nanoTime() < deadline) {
            val tick = CountDownLatch(1)
            SwingUtilities.invokeLater { tick.countDown() }
            tick.await(100, TimeUnit.MILLISECONDS)
        }
        assertTrue(settled.size > before, "the save never settled")
        // Flush the EDT tail the save posted.
        SwingUtilities.invokeAndWait {}
    }

    private fun renderedText(notice: SubtleNotice): String {
        val pane = ChatPanelTestHarness.find(notice, JTextPane::class.java) { true }!!
        return pane.document.getText(0, pane.document.length)
    }

    private inner class Fixture(
        savedBackendId: String,
    ) {
        val strings = mutableMapOf(PREFERRED_KEY to savedBackendId)
        private val setStringKeys = CopyOnWriteArrayList<String>()
        val output = CopyOnWriteArrayList<String>()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

        init {
            val prefs = inMemoryPreferences()
            val logging = mock<Logging>()
            whenever(logging.logToOutput(any<String>())).thenAnswer {
                output.add(it.getArgument(0))
                null
            }
            whenever(api.persistence().preferences()).thenReturn(prefs)
            whenever(api.logging()).thenReturn(logging)
        }

        val registry = BackendRegistry(api)

        fun panel(): SettingsPanel {
            val panel =
                SettingsPanel(
                    api = api,
                    settingsRepo = AgentSettingsRepository(api),
                    backends = registry,
                    supervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    audit = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    buildIdentity = "Custom AI Agent test (test build)",
                )
            panels.add(panel)
            return panel
        }

        fun storedBackend(): String? = strings[PREFERRED_KEY]

        fun preferredBackendWrites(): Int = setStringKeys.count { it == PREFERRED_KEY }

        private fun inMemoryPreferences(): Preferences {
            val booleans = mutableMapOf<String, Boolean>()
            val integers = mutableMapOf<String, Int>()
            val prefs = mock<Preferences>()
            whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
            whenever(prefs.setString(any(), any())).thenAnswer {
                setStringKeys.add(it.getArgument(0))
                strings[it.getArgument<String>(0)] = it.getArgument(1)
                null
            }
            whenever(prefs.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
            whenever(prefs.setBoolean(any(), any())).thenAnswer {
                booleans[it.getArgument<String>(0)] = it.getArgument(1)
                null
            }
            whenever(prefs.getInteger(any())).thenAnswer { integers[it.getArgument<String>(0)] }
            whenever(prefs.setInteger(any(), any())).thenAnswer {
                integers[it.getArgument<String>(0)] = it.getArgument(1)
                null
            }
            return prefs
        }
    }

    private companion object {
        const val PREFERRED_KEY = "backend.preferred"
    }
}
