package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.ContributionSnapshot
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
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.util.concurrent.CopyOnWriteArrayList
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.SwingUtilities

/**
 * Phase 29 / D-07 — the core host for [SettingsContribution]: slot placement (UI-SPEC PC-9, H-1),
 * the empty store build (M1, Rule F-2) and a contribution whose `createComponent` throws (PC-10, M4).
 *
 * Contributions are passed to the panel directly. No test registers a provider through
 * `META-INF/services`, so the store test classpath keeps its real, empty provider list.
 */
class SettingsContributionHostTest {
    private val panels = CopyOnWriteArrayList<SettingsPanel>()

    @AfterEach
    fun shutdownPanels() {
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    @Test
    fun theStoreClasspathHasNoContributionAndTheDefaultPanelHostsNone() {
        assertTrue(
            Plugins.load(SettingsContribution::class.java).isEmpty(),
            "D-07: the store build ships no SettingsContribution provider.",
        )
        val fixture = newFixture(contributions = null)
        onEdt {
            assertTrue(fixture.panel.activeContributions.isEmpty(), "The default panel loads no contribution.")
            assertEquals(CORE_CARD_IDS, fixture.panel.backendConfigPanel.cardIds(), "No card is added.")
        }
    }

    @Test
    fun aBackendCardContributionForAnIdWithNoCoreCardGetsANewCard() {
        val contribution = RecordingContribution("test.newcard", SettingsSlot.BACKEND_CARD, backendId = "x-test-cli")
        val fixture = newFixture(listOf(contribution))
        onEdt {
            val backendPanel = fixture.panel.backendConfigPanel
            assertEquals(CORE_CARD_IDS + "x-test-cli", backendPanel.cardIds(), "One new card, registered last.")
            val card = backendPanel.cardFor("x-test-cli")
            assertNotNull(card, "A card is registered under the contributed id.")
            assertTrue(
                SwingUtilities.isDescendingFrom(contribution.component, card!!),
                "The contributed component is the content of the new card.",
            )
            backendPanel.setBackend("x-test-cli")
            assertTrue(card.isVisible, "setBackend shows the contributed card.")
        }
    }

    @Test
    fun aBackendCardContributionForOllamaIsAppendedBelowTheCoreCardsLastRow() {
        val contribution = RecordingContribution("test.ollama", SettingsSlot.BACKEND_CARD, backendId = "ollama")
        val fixture = newFixture(listOf(contribution))
        onEdt {
            val backendPanel = fixture.panel.backendConfigPanel
            assertEquals(CORE_CARD_IDS, backendPanel.cardIds(), "Ollama has a core card, so no card is added.")
            val card = backendPanel.cardFor("ollama")!!
            assertSame(card, contribution.component.parent, "UI-SPEC PC-9: appended to the core Ollama card.")
            assertSame(
                contribution.component,
                card.getComponent(card.componentCount - 1),
                "UI-SPEC PC-9: the contribution is the card's last child.",
            )
            val layout = card.layout as java.awt.GridBagLayout
            val rowOf = { c: Component -> layout.getConstraints(c).gridy }
            val contributedRow = rowOf(contribution.component)
            assertTrue(
                card.components.filter { it !== contribution.component }.all { rowOf(it) < contributedRow },
                "UI-SPEC PC-9: the contribution sits below the card's last row.",
            )
        }
    }

    @Test
    fun anMcpTabContributionIsTheLastChildOfTheMcpStackWithNoHostGap() {
        val contribution = RecordingContribution("test.mcp", SettingsSlot.MCP_TAB)
        val fixture = newFixture(listOf(contribution))
        onEdt {
            val stack = contribution.component.parent as JPanel
            assertEquals(BoxLayout.Y_AXIS, (stack.layout as BoxLayout).axis, "The mcpSection Y_AXIS stack.")
            assertTrue(SwingUtilities.isDescendingFrom(stack, fixture.panel.mcpTab), "Inside the MCP Server tab.")
            assertEquals(MCP_STACK_CORE_CHILDREN + 1, stack.componentCount, "Core sections, then the contribution.")
            assertSame(contribution.component, stack.getComponent(stack.componentCount - 1), "Last child.")
            assertFalse(
                stack.components.any { it is Box.Filler },
                "UI-SPEC PC-9 / H-3: the host adds no rigid area or strut to the MCP stack.",
            )
        }
    }

    @Test
    fun anActiveScannerContributionFollowsScanParametersInTheSameBodyAfterASmallGap() {
        val contribution = RecordingContribution("test.active", SettingsSlot.ACTIVE_SCANNER_TAB)
        val fixture = newFixture(listOf(contribution))
        onEdt {
            val body = contribution.component.parent as JPanel
            assertTrue(SwingUtilities.isDescendingFrom(body, fixture.panel.activeScannerTab), "Inside the tab.")
            val children = body.components.toList()
            assertEquals(ACTIVE_BODY_CORE_CHILDREN + 2, children.size, "Core body, one gap, the contribution.")
            assertTrue(accordionTitled(children[0], "Scanner control"), "Child 0 is the Scanner control accordion.")
            assertTrue(accordionTitled(children[2], "Scan parameters"), "Child 2 is the Scan parameters accordion.")
            val gap = children[3]
            assertTrue(gap is Box.Filler, "UI-SPEC PC-9: a rigid area precedes the contribution.")
            assertEquals(DesignTokens.Spacing.sm, gap.preferredSize.height, "The gap is Spacing.sm high.")
            assertEquals(0, gap.preferredSize.width, "The gap is vertical only.")
            assertSame(contribution.component, children[4], "The contribution follows Scan parameters.")
        }
    }

    @Test
    fun severalContributionsInOneSlotStackInListOrder() {
        val mcpFirst = RecordingContribution("test.mcp.a", SettingsSlot.MCP_TAB)
        val mcpSecond = RecordingContribution("test.mcp.b", SettingsSlot.MCP_TAB)
        val activeFirst = RecordingContribution("test.active.a", SettingsSlot.ACTIVE_SCANNER_TAB)
        val activeSecond = RecordingContribution("test.active.b", SettingsSlot.ACTIVE_SCANNER_TAB)
        val cardFirst = RecordingContribution("test.card.a", SettingsSlot.BACKEND_CARD, backendId = "z-first")
        val cardSecond = RecordingContribution("test.card.b", SettingsSlot.BACKEND_CARD, backendId = "a-second")
        val fixture =
            newFixture(listOf(mcpFirst, activeFirst, cardFirst, mcpSecond, activeSecond, cardSecond))
        onEdt {
            val stack = mcpFirst.component.parent as JPanel
            assertEquals(
                listOf<Component>(mcpFirst.component, mcpSecond.component),
                stack.components.takeLast(2),
                "UI-SPEC H-1: MCP_TAB contributions in list order.",
            )
            val body = activeFirst.component.parent as JPanel
            val tail = body.components.takeLast(4)
            assertTrue(tail[0] is Box.Filler && tail[2] is Box.Filler, "UI-SPEC PC-9: a gap before each one.")
            assertSame(activeFirst.component, tail[1], "UI-SPEC H-1: first active-scanner contribution first.")
            assertSame(activeSecond.component, tail[3], "UI-SPEC H-1: second one second.")
            assertEquals(
                CORE_CARD_IDS + listOf("z-first", "a-second"),
                fixture.panel.backendConfigPanel.cardIds(),
                "UI-SPEC H-1: new cards in list order, not sorted by id.",
            )
            assertEquals(
                listOf(mcpFirst, activeFirst, cardFirst, mcpSecond, activeSecond, cardSecond),
                fixture.panel.activeContributions,
                "The host keeps the list order.",
            )
        }
    }

    @Test
    fun withNoContributionEveryHostRendersExactlyWhatItRenderedBefore() {
        val fixture = newFixture(emptyList())
        onEdt {
            val panel = fixture.panel
            assertEquals(MCP_STACK_CORE_CHILDREN, panel.mcpSection().componentCount, "M1: the MCP stack is unchanged.")
            assertEquals(
                ACTIVE_BODY_CORE_CHILDREN,
                panel.activeAiScannerSection().componentCount,
                "M1: the active-scanner body is unchanged, with no trailing gap.",
            )
            assertEquals(CORE_CARD_IDS, panel.backendConfigPanel.cardIds(), "M1: no backend card is added.")
            listOf(panel.generalTab, panel.mcpTab, panel.activeScannerTab).forEach { tab ->
                assertFalse(
                    labelsUnder(tab).any { it.text.orEmpty().contains("full build only", ignoreCase = true) },
                    "Rule F-2: no placeholder text for an absent contribution.",
                )
            }
        }
    }

    @Test
    fun aContributionWhoseCreateComponentThrowsIsLoggedSkippedAndTheWindowStillOpens() {
        val throwing = ThrowingContribution()
        val working = RecordingContribution("test.active", SettingsSlot.ACTIVE_SCANNER_TAB)
        val fixture = newFixture(listOf(throwing, working))
        onEdt {
            val logged = argumentCaptor<String>()
            verify(fixture.api.logging(), atLeastOnce()).logToError(logged.capture())
            assertTrue(
                logged.allValues.any { it.contains(ThrowingContribution::class.java.name) && it.contains("boom") },
                "UI-SPEC PC-10: the error output names the contribution class and the message. Logged: ${logged.allValues}",
            )
            assertEquals(listOf<SettingsContribution>(working), fixture.panel.activeContributions, "Dropped.")
            assertTrue(
                SwingUtilities.isDescendingFrom(working.component, fixture.panel.activeScannerTab),
                "UI-SPEC PC-10: the other contributions are still placed.",
            )
            assertEquals(MCP_STACK_CORE_CHILDREN, fixture.panel.mcpSection().componentCount, "Nothing in its slot.")
        }
        assertEquals(listOf("create"), throwing.calls, "No member but createComponent ever runs on it.")
    }

    // ------------------------------------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------------------------------------

    internal class Fixture(
        val panel: SettingsPanel,
        val api: MontoyaApi,
        val repo: AgentSettingsRepository,
        val backends: BackendRegistry,
        val supervisor: AgentSupervisor,
        val mcpSupervisor: McpSupervisor,
        val activeAiScanner: ActiveAiScanner,
        val preferenceWrites: CopyOnWriteArrayList<String>,
    )

    /** [contributions] null builds the panel with its production default (`Plugins.load`). */
    internal fun newFixture(contributions: List<SettingsContribution>?): Fixture {
        val writes = CopyOnWriteArrayList<String>()
        val preferences = inMemoryPreferences(writes)
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val supervisor: AgentSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val mcpSupervisor: McpSupervisor = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val passiveAiScanner: PassiveAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val activeAiScanner: ActiveAiScanner = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val repo = AgentSettingsRepository(api)
        val audit = mock<AuditLogger>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val panel =
            if (contributions == null) {
                SettingsPanel(
                    api = api,
                    settingsRepo = repo,
                    backends = backends,
                    supervisor = supervisor,
                    audit = audit,
                    mcpSupervisor = mcpSupervisor,
                    passiveAiScanner = passiveAiScanner,
                    activeAiScanner = activeAiScanner,
                )
            } else {
                SettingsPanel(
                    api = api,
                    settingsRepo = repo,
                    backends = backends,
                    supervisor = supervisor,
                    audit = audit,
                    mcpSupervisor = mcpSupervisor,
                    passiveAiScanner = passiveAiScanner,
                    activeAiScanner = activeAiScanner,
                    contributions = contributions,
                )
            }
        panels.add(panel)
        return Fixture(panel, api, repo, backends, supervisor, mcpSupervisor, activeAiScanner, writes)
    }

    private fun inMemoryPreferences(writes: MutableList<String>): Preferences {
        val strings = mutableMapOf<String, String>()
        val booleans = mutableMapOf<String, Boolean>()
        val integers = mutableMapOf<String, Int>()
        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
            writes.add(it.getArgument(0))
            strings[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getBoolean(any())).thenAnswer { booleans[it.getArgument<String>(0)] }
        whenever(prefs.setBoolean(any(), any())).thenAnswer {
            writes.add(it.getArgument(0))
            booleans[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        whenever(prefs.getInteger(any())).thenAnswer { integers[it.getArgument<String>(0)] }
        whenever(prefs.setInteger(any(), any())).thenAnswer {
            writes.add(it.getArgument(0))
            integers[it.getArgument<String>(0)] = it.getArgument(1)
            null
        }
        return prefs
    }

    internal data class TextSnapshot(
        val value: String,
    ) : ContributionSnapshot

    /** One recorded call: the member, the thread it ran on and whether that thread was the EDT. */
    internal data class Call(
        val member: String,
        val thread: String,
        val onEdt: Boolean,
    )

    /** A contribution that records every call. Its component holds one text field. */
    internal open class RecordingContribution(
        override val sectionId: String,
        override val slot: SettingsSlot,
        override val backendId: String? = null,
    ) : SettingsContribution {
        val recorded = CopyOnWriteArrayList<Call>()
        val field = JTextField("initial")
        lateinit var component: JPanel
        var persistFailure: RuntimeException? = null
        var onPersist: (TextSnapshot) -> Unit = {}
        val key = "full.test.$sectionId"

        val members: List<String> get() = recorded.map { it.member }

        fun callsOf(member: String): List<Call> = recorded.filter { it.member == member }

        private fun record(member: String) {
            recorded.add(Call(member, Thread.currentThread().name, SwingUtilities.isEventDispatchThread()))
        }

        override fun ownedKeys(): Set<String> = setOf(key)

        override fun createComponent(context: SettingsContributionContext): JComponent {
            record("create")
            field.text = context.store.getString(key) ?: "initial"
            component = JPanel().apply { add(field) }
            return component
        }

        override fun collect(): ContributionSnapshot {
            record("collect")
            return TextSnapshot(field.text)
        }

        override fun persist(
            snapshot: ContributionSnapshot,
            store: PluginSettingsStore,
        ) {
            record("persist")
            val text = snapshot as TextSnapshot
            onPersist(text)
            persistFailure?.let { throw it }
            store.setString(key, text.value)
        }

        override fun defaults(): ContributionSnapshot = TextSnapshot("default")

        override fun applyToUi(snapshot: ContributionSnapshot) {
            record("applyToUi")
            field.text = (snapshot as TextSnapshot).value
        }

        override fun onCoreSettingsApplied(settings: AgentSettings) {
            record("onCoreSettingsApplied")
        }
    }

    /** A contribution whose createComponent throws; records every member call. */
    internal class ThrowingContribution : SettingsContribution {
        val calls = CopyOnWriteArrayList<String>()
        override val sectionId = "test.throwing"
        override val slot = SettingsSlot.MCP_TAB

        override fun ownedKeys(): Set<String> {
            calls.add("ownedKeys")
            return setOf("full.test.throwing")
        }

        override fun createComponent(context: SettingsContributionContext): JComponent {
            calls.add("create")
            throw IllegalStateException("boom")
        }

        override fun collect(): ContributionSnapshot {
            calls.add("collect")
            return TextSnapshot("")
        }

        override fun persist(
            snapshot: ContributionSnapshot,
            store: PluginSettingsStore,
        ) {
            calls.add("persist")
        }

        override fun defaults(): ContributionSnapshot {
            calls.add("defaults")
            return TextSnapshot("")
        }

        override fun applyToUi(snapshot: ContributionSnapshot) {
            calls.add("applyToUi")
        }

        override fun onCoreSettingsApplied(settings: AgentSettings) {
            calls.add("onCoreSettingsApplied")
        }
    }

    internal fun onEdt(block: () -> Unit) {
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                block()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it }
    }

    private fun accordionTitled(
        component: Component,
        title: String,
    ): Boolean = component is AccordionPanel && labelsUnder(component).any { it.text == title }

    private fun labelsUnder(root: Component): List<JLabel> {
        val found = mutableListOf<JLabel>()

        fun walk(c: Component) {
            if (c is JLabel) found.add(c)
            if (c is Container) c.components.forEach { walk(it) }
        }
        walk(root)
        return found
    }

    companion object {
        /** The 1.0.1 backend cards, in registration order. */
        val CORE_CARD_IDS =
            listOf(
                "burp-ai",
                "codex-cli",
                "gemini-cli",
                "opencode-cli",
                "claude-cli",
                "ollama",
                "lmstudio",
                "openai-compatible",
                "nvidia-nim",
                "perplexity",
                "anthropic",
                "copilot-cli",
            )

        /** The core McpConfigPanel section and the External MCP Servers section. */
        const val MCP_STACK_CORE_CHILDREN = 2

        /** "Scanner control", the Spacing.sm rigid area and "Scan parameters". */
        const val ACTIVE_BODY_CORE_CHILDREN = 3
    }
}
