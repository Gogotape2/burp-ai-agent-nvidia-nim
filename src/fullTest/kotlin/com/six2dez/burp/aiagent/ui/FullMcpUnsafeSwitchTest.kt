package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.ui.components.SafetyIndicator
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.lang.reflect.InvocationTargetException
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList
import javax.swing.JTextPane
import javax.swing.SwingUtilities

/**
 * Phase 31 / D-13 — the full-flavor counterpart of McpUnsafeSwitchTest: the full catalog has unsafe tools,
 * so the Unsafe switch, the MCP notice and the header safety level behave exactly as in 1.0.1.
 */
class FullMcpUnsafeSwitchTest {
    @TempDir
    lateinit var root: Path

    private val panels = CopyOnWriteArrayList<SettingsPanel>()

    @AfterEach
    fun releaseFixtures() {
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    @Test
    fun theFullCatalogHasUnsafeToolsAndTheSwitchIsLive() {
        assertTrue(McpToolCatalog.hasUnsafeTools(), "The full build ships unsafeOnly tools.")
        val panel = newPanel(savedUnsafe = true)
        onEdt {
            assertTrue(panel.mcpUnsafe.isEnabled, "With unsafe tools the switch is enabled, as in 1.0.1.")
            assertTrue(panel.mcpUnsafe.isSelected)
            assertEquals(
                "Allows tools that modify Burp state, write files, or send active requests.",
                panel.mcpUnsafe.toolTipText,
                "The 1.0.1 tooltip is kept.",
            )
            assertFalse(panel.mcpUnsafeNote.isVisible, "The no-unsafe-tools note stays hidden.")
        }
    }

    @Test
    fun externalAccessWithUnsafeOnStillRaisesTheUnsafeRiskItemAndRiskLevel() {
        val panel = newPanel(savedUnsafe = true)
        onEdt {
            panel.mcpEnabled.isSelected = true
            panel.mcpExternal.isSelected = true
            panel.refreshMcpNotice()
            assertTrue(panel.mcpNotice.isVisible, "Anti-vacuity: the notice is shown.")
            assertTrue(noticeText(panel).contains("External MCP + Unsafe mode"), "The 1.0.1 RISK item is kept.")
            val settings = panel.currentSettings()
            assertEquals(
                SafetyIndicator.Level.RISK,
                SafetySummary.safetyLevel(settings, McpToolCatalog.hasUnsafeTools()),
                "MCP external with Unsafe on is RISK in the full build.",
            )
            assertTrue(SafetySummary.tooltip(settings, McpToolCatalog.hasUnsafeTools()).contains("Unsafe on"))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    private fun noticeText(panel: SettingsPanel): String =
        descendants(panel.mcpNotice)
            .filterIsInstance<JTextPane>()
            .joinToString(" ") { it.text }
            .replace(Regex("\\s+"), " ")

    private fun descendants(container: Container): List<Component> =
        container.components.flatMap { child ->
            listOf(child) + if (child is Container) descendants(child) else emptyList()
        }

    private fun onEdt(block: () -> Unit) {
        try {
            SwingUtilities.invokeAndWait(block)
        } catch (wrapped: InvocationTargetException) {
            throw wrapped.cause ?: wrapped
        }
    }

    private fun newApi(booleans: MutableMap<String, Boolean> = mutableMapOf()): MontoyaApi {
        val strings = mutableMapOf<String, String>()
        val integers = mutableMapOf<String, Int>()
        val prefs = mock<Preferences>()
        whenever(prefs.getString(any())).thenAnswer { strings[it.getArgument<String>(0)] }
        whenever(prefs.setString(any(), any())).thenAnswer {
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
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return api
    }

    private fun newPanel(savedUnsafe: Boolean): SettingsPanel {
        val repo = AgentSettingsRepository(newApi(mutableMapOf(KEY_MCP_UNSAFE to savedUnsafe)))
        val backends: BackendRegistry = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(backends.listAllBackendIds()).thenReturn(listOf("codex-cli", "ollama"))
        val panel =
            SettingsPanel(
                api = newApi(),
                settingsRepo = repo,
                backends = backends,
                supervisor = mock<AgentSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                audit = AuditLogger(newApi(), root.resolve("audit-home").toFile()),
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                buildIdentity = "Custom AI Agent test (full test build)",
                contributions = emptyList(),
            )
        panels.add(panel)
        return panel
    }

    private companion object {
        const val KEY_MCP_UNSAFE = "mcp.unsafe.enabled"
    }
}
