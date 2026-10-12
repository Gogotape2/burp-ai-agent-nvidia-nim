package com.six2dez.burp.aiagent.full.autoqueue

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.PluginHost
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.SwingUtilities

/**
 * Phase 29 plan 29-16 / D-02 — the full build's opt-in passive-to-active auto-queue.
 *
 * The plug-in installs a SuggestedTargetSink on the passive scanner that forwards the offered targets to
 * the AI Active Scanner only when its own key `full.active.autoqueue.enabled` is true AND the active
 * scanner is enabled. An absent key means OFF, including on an install whose stored 1.0.1 setting
 * `active.ai.auto.passive` is true (T-29-34): the plug-in never reads that key.
 *
 * The contribution half pins the UI-SPEC S18 / PC-13 control on the Active Scanner tab.
 */
class AutoQueuePluginTest {
    private val prefs = InMemoryPreferences()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val store: PluginSettingsStore
    private val logLines = mutableListOf<String>()
    private val activeScanner = mock<ActiveAiScanner>()
    private val passiveScanner: PassiveAiScanner
    private val plugin = AutoQueuePlugin()

    init {
        whenever(api.persistence().preferences()).thenReturn(prefs)
        store = AgentSettingsRepository(api).pluginSettings()
        passiveScanner = PassiveAiScanner(api, mock<AgentSupervisor>(), mock<AuditLogger>()) { TestSettings.baselineSettings() }
    }

    @AfterEach
    fun tearDown() {
        plugin.shutdown()
        passiveScanner.shutdown()
    }

    // ── The sink ────────────────────────────────────────────────────────────────────────────────

    @Test
    fun installSetsTheSinkOnThePassiveScanner() {
        install()

        assertNotNull(passiveScanner.suggestedTargetSink, "the plug-in installs its sink")
    }

    @Test
    fun aFreshInstallQueuesNothing() {
        install()

        offer(TARGETS, scannerOn())

        verifyNoInteractions(activeScanner)
        assertEquals(emptyList<String>(), logLines)
    }

    @Test
    fun theLegacyAutoQueueSettingAloneQueuesNothing() {
        // An install upgraded from 1.0.1 with the old core auto-queue ON (its default).
        prefs.booleans[LEGACY_KEY] = true
        install()

        offer(TARGETS, scannerOn())

        verifyNoInteractions(activeScanner)
        assertEquals(0, prefs.writeCount(AutoQueuePlugin.KEY), "the plug-in does not migrate the legacy value")
    }

    @Test
    fun theNewToggleAndTheActiveScannerOnQueueEveryOfferedTargetOnce() {
        prefs.booleans[AutoQueuePlugin.KEY] = true
        install()

        offer(TARGETS, scannerOn())

        TARGETS.forEach { verify(activeScanner).queueTarget(it) }
        assertEquals(listOf("[AutoQueue] Queued 2 suggested target(s) to the Active Scanner"), logLines)
    }

    @Test
    fun theNewToggleWithTheActiveScannerOffQueuesNothing() {
        prefs.booleans[AutoQueuePlugin.KEY] = true
        install()

        offer(TARGETS, scannerOn().copy(activeAiEnabled = false))

        verifyNoInteractions(activeScanner)
        assertEquals(emptyList<String>(), logLines)
    }

    @Test
    fun theToggleIsReadOnEveryOffer() {
        install()
        offer(TARGETS, scannerOn())
        verifyNoInteractions(activeScanner)

        prefs.booleans[AutoQueuePlugin.KEY] = true
        offer(TARGETS.take(1), scannerOn())

        verify(activeScanner).queueTarget(TARGETS.first())
    }

    @Test
    fun shutdownRemovesTheSink() {
        install()

        plugin.shutdown()

        assertNull(passiveScanner.suggestedTargetSink, "unload leaves the passive scanner with no sink")
    }

    @Test
    fun thePluginIsRegisteredThroughTheServicesFile() {
        assertEquals(
            listOf(AutoQueuePlugin::class.java.name),
            Plugins.load(ExtensionPlugin::class.java).map { it.javaClass.name },
        )
    }

    // ── The Active Scanner tab contribution ─────────────────────────────────────────────────────

    @Test
    fun theContributionOwnsOnlyTheNewKeyOnTheActiveScannerTab() {
        val contribution = AutoQueueContribution()

        assertEquals(SettingsSlot.ACTIVE_SCANNER_TAB, contribution.slot)
        assertEquals("active.autoqueue", contribution.sectionId)
        assertEquals(setOf("full.active.autoqueue.enabled"), contribution.ownedKeys())
        assertEquals(AutoQueueSnapshot(enabled = false), contribution.defaults(), "Restore defaults turns it OFF")
        assertEquals(
            listOf(AutoQueueContribution::class.java.name),
            Plugins.load(SettingsContribution::class.java).filter { it.slot == SettingsSlot.ACTIVE_SCANNER_TAB }.map { it.javaClass.name },
            "the full build's one Active Scanner tab contribution is registered through the services file",
        )
    }

    @Test
    fun persistWritesOnlyTheNewKey() {
        val contribution = AutoQueueContribution()

        contribution.persist(AutoQueueSnapshot(enabled = true), store)
        assertEquals(true, prefs.booleans[AutoQueuePlugin.KEY])
        contribution.persist(contribution.defaults(), store)
        assertEquals(false, prefs.booleans[AutoQueuePlugin.KEY])

        assertEquals(listOf(AutoQueuePlugin.KEY, AutoQueuePlugin.KEY), prefs.writes, "no other key is written")
        assertFalse(LEGACY_KEY in prefs.booleans, "the legacy key is never written")
    }

    @Test
    fun theControlIsTheAutoQueueAccordionWithOneRow() {
        val contribution = AutoQueueContribution()

        onEdt {
            val component = contribution.createComponent(context())
            val accordion = component as? AccordionPanel
            assertNotNull(accordion, "the component is an AccordionPanel, got ${component.javaClass.name}")
            assertTrue(accordion!!.isExpanded(), "initially expanded")
            val labels = descendants<JLabel>(component).map { it.text }
            assertTrue(TITLE in labels, "title: $labels")
            assertTrue(SUBTITLE in labels, "subtitle: $labels")
            assertTrue(ROW_LABEL in labels, "row label: $labels")

            val checkbox = descendants<JCheckBox>(component).single()
            assertEquals(CHECKBOX_TEXT, checkbox.text)
            assertEquals(TOOLTIP, checkbox.toolTipText)
            assertEquals(DesignTokens.Typography.body, checkbox.font)
            assertEquals(DesignTokens.Colors.surface, checkbox.background)
            assertEquals(DesignTokens.Colors.onSurface, checkbox.foreground)
        }
    }

    @Test
    fun theCheckboxStartsOffOnAFreshInstallAndWithOnlyTheLegacyKey() {
        prefs.booleans[LEGACY_KEY] = true
        val contribution = AutoQueueContribution()

        onEdt {
            val checkbox = descendants<JCheckBox>(contribution.createComponent(context())).single()
            assertFalse(checkbox.isSelected, "OFF by default, legacy key ignored (D-02)")
            assertEquals(AutoQueueSnapshot(enabled = false), contribution.collect())
        }
    }

    @Test
    fun theCheckboxShowsTheStoredValueAndRoundTripsThroughApplyAndCollect() {
        prefs.booleans[AutoQueuePlugin.KEY] = true
        val contribution = AutoQueueContribution()

        onEdt {
            val checkbox = descendants<JCheckBox>(contribution.createComponent(context())).single()
            assertTrue(checkbox.isSelected, "starts from the stored value")
            contribution.applyToUi(AutoQueueSnapshot(enabled = false))
            assertFalse(checkbox.isSelected)
            assertEquals(AutoQueueSnapshot(enabled = false), contribution.collect())
        }
    }

    @Test
    fun theCheckboxStaysEnabledWhenTheActiveScannerIsOff() {
        val contribution = AutoQueueContribution()

        onEdt {
            val checkbox = descendants<JCheckBox>(contribution.createComponent(context())).single()
            contribution.onCoreSettingsApplied(TestSettings.baselineSettings().copy(activeAiEnabled = false))
            assertTrue(checkbox.isEnabled, "1.0.1 parity: never disabled by 'Enable scanner'")
        }
    }

    @Test
    fun everyNewSingleLineStringFitsTheOverflowRule() {
        listOf(TITLE, SUBTITLE, ROW_LABEL, CHECKBOX_TEXT).forEach { text ->
            assertTrue(text.length <= MAX_SINGLE_LINE, "'$text' is ${text.length} characters")
        }
        assertEquals(53, SUBTITLE.length, "UI-SPEC Overflow rule: the auto-queue subtitle is 53 characters")
    }

    private fun install() =
        plugin.install(
            PluginHost(
                api = api,
                pluginSettings = store,
                passiveScanner = passiveScanner,
                activeScanner = activeScanner,
                log = { logLines += it },
            ),
        )

    private fun offer(
        targets: List<ActiveScanTarget>,
        settings: AgentSettings,
    ) {
        val sink = passiveScanner.suggestedTargetSink
        assertNotNull(sink, "the plug-in must be installed")
        sink!!.offer(targets, settings)
    }

    private fun scannerOn(): AgentSettings = TestSettings.baselineSettings().copy(activeAiEnabled = true)

    private fun context() =
        SettingsContributionContext(
            api = api,
            store = store,
            coreSettings = { TestSettings.baselineSettings() },
            dialogParent = { null },
            testConnection = {},
        )

    private inline fun <reified T : Component> descendants(root: Component): List<T> = allComponents(root).filterIsInstance<T>()

    private fun allComponents(root: Component): List<Component> {
        val children = (root as? Container)?.components.orEmpty()
        return listOf(root) + children.flatMap { allComponents(it) }
    }

    private fun onEdt(body: () -> Unit) {
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                body()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it }
    }

    private companion object {
        const val LEGACY_KEY = "active.ai.auto.passive"
        const val TITLE = "Auto-queue"
        const val SUBTITLE = "Off by default. Sends requests to the target when on."
        const val ROW_LABEL = "Auto-queue findings"
        const val CHECKBOX_TEXT = "Auto-queue passive findings for active testing"
        const val TOOLTIP =
            "Off by default. When on, AI passive findings are queued to the Active Scanner, which sends requests to the target."
        const val MAX_SINGLE_LINE = 60

        val TARGETS: List<ActiveScanTarget> =
            listOf("id", "q").map { name ->
                ActiveScanTarget(
                    originalRequest = mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                    injectionPoint = InjectionPoint(InjectionType.URL_PARAM, name, "1"),
                    vulnHint = VulnHint(VulnClass.SQLI, 90, "evidence"),
                    priority = 80,
                )
            }
    }
}
