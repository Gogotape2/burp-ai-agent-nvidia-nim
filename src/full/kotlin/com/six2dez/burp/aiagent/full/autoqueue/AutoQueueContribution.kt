package com.six2dez.burp.aiagent.full.autoqueue

import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import javax.swing.JComponent
import javax.swing.JPanel

data class AutoQueueSnapshot(
    val enabled: Boolean,
) : ContributionSnapshot

// RED skeleton (29-16 Task 2): replaced by the real contribution in the GREEN commit.
class AutoQueueContribution : SettingsContribution {
    override val sectionId: String = ""
    override val slot: SettingsSlot = SettingsSlot.MCP_TAB

    override fun ownedKeys(): Set<String> = emptySet()

    override fun createComponent(context: SettingsContributionContext): JComponent = JPanel()

    override fun collect(): ContributionSnapshot = AutoQueueSnapshot(enabled = true)

    override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {}

    override fun defaults(): ContributionSnapshot = AutoQueueSnapshot(enabled = true)

    override fun applyToUi(snapshot: ContributionSnapshot) {}
}
