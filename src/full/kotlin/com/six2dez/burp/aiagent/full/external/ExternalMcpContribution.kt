package com.six2dez.burp.aiagent.full.external

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.ui.panels.ExternalServersPanel
import javax.swing.JComponent

/** What the External MCP Servers panel holds: the server list, bearer tokens in plaintext. */
data class ExternalServersSnapshot(
    val servers: List<ExternalMcpServerConfig>,
) : ContributionSnapshot

/**
 * Phase 29 / NET-02, D-07, BUILD-03 — the full build's External MCP Servers section on the MCP Server
 * tab, contributed through `META-INF/services/com.six2dez.burp.aiagent.spi.SettingsContribution`. The
 * store build has neither this class nor the panel, so its MCP tab ends with the core sections.
 *
 * The panel is the 1.0.1 [ExternalServersPanel], unchanged, built from the list [ExternalMcpSettings]
 * loads and the core MCP settings' stdio switch. Save persists the panel's list under the 1.0.1 key;
 * Restore defaults empties it, as the 1.0.1 core defaults did. The MCP server's "Allow external access"
 * switch (`mcp.external.enabled`) is a core setting and stays in the core panel (D-06 correction).
 */
class ExternalMcpContribution : SettingsContribution {
    override val sectionId: String = "mcp.external"
    override val slot: SettingsSlot = SettingsSlot.MCP_TAB

    /** Built in [createComponent] on the EDT; the host calls no other UI member before it. */
    private lateinit var panel: ExternalServersPanel

    // Set on the EDT in createComponent, read by persist on the settings-save worker.
    @Volatile
    private var logError: (String) -> Unit = {}

    override fun ownedKeys(): Set<String> = setOf(ExternalMcpSettings.KEY)

    override fun createComponent(context: SettingsContributionContext): JComponent {
        val log: (String) -> Unit = { line -> context.api.logging().logToError(line) }
        logError = log
        panel =
            ExternalServersPanel(
                initialServers = ExternalMcpSettings(context.store, log).load(),
                stdioEnabled = context.coreSettings().mcpSettings.stdioEnabled,
            )
        return panel.buildPanel()
    }

    override fun collect(): ContributionSnapshot = ExternalServersSnapshot(panel.getServers())

    override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {
        ExternalMcpSettings(store, logError).save((snapshot as ExternalServersSnapshot).servers)
    }

    override fun defaults(): ContributionSnapshot = ExternalServersSnapshot(emptyList())

    override fun applyToUi(snapshot: ContributionSnapshot) {
        panel.setServers((snapshot as ExternalServersSnapshot).servers)
    }

    override fun onCoreSettingsApplied(settings: AgentSettings) {
        panel.setStdioEnabled(settings.mcpSettings.stdioEnabled)
    }
}
