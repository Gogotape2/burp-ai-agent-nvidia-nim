package com.six2dez.burp.aiagent.full.external

import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import javax.swing.JComponent
import javax.swing.JPanel

/** What the External MCP Servers panel holds: the server list, bearer tokens in plaintext. */
data class ExternalServersSnapshot(
    val servers: List<ExternalMcpServerConfig>,
) : ContributionSnapshot

/** RED skeleton (29-15 Task 1): replaced by the implementation in the GREEN commit. */
class ExternalMcpContribution : SettingsContribution {
    override val sectionId: String = "skeleton"
    override val slot: SettingsSlot = SettingsSlot.BACKEND_CARD

    override fun ownedKeys(): Set<String> = emptySet()

    override fun createComponent(context: SettingsContributionContext): JComponent = JPanel()

    override fun collect(): ContributionSnapshot = ExternalServersSnapshot(emptyList())

    override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {
        // RED skeleton: writes nothing.
    }

    override fun defaults(): ContributionSnapshot = ExternalServersSnapshot(emptyList())

    override fun applyToUi(snapshot: ContributionSnapshot) {
        // RED skeleton.
    }
}
