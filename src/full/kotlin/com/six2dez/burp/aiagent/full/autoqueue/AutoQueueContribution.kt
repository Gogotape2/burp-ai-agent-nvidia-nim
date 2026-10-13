package com.six2dez.burp.aiagent.full.autoqueue

import com.six2dez.burp.aiagent.spi.ContributionSnapshot
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import com.six2dez.burp.aiagent.ui.components.AccordionPanel
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.addRowFull
import com.six2dez.burp.aiagent.ui.design.formGrid
import javax.swing.JCheckBox
import javax.swing.JComponent

/** What the auto-queue control holds: whether the toggle is on. */
data class AutoQueueSnapshot(
    val enabled: Boolean,
) : ContributionSnapshot

/**
 * Phase 29 / D-02, D-07 — the full build's "Auto-queue" section on the AI Active Scanner tab, after
 * "Scan parameters" (UI-SPEC S18, PC-13), contributed through
 * `META-INF/services/com.six2dez.burp.aiagent.spi.SettingsContribution`.
 *
 * One checkbox bound to [AutoQueuePlugin.KEY], OFF unless that key is stored true; the 1.0.1 core
 * auto-queue preference is never read or written (D-02). The checkbox is not disabled when "Enable
 * scanner" is off (1.0.1 parity): the sink queues nothing unless both are on. It styles through
 * `DesignTokens` getters at build time only and keeps no color or font in a field (UI-SPEC H-3).
 */
class AutoQueueContribution : SettingsContribution {
    override val sectionId: String = "active.autoqueue"
    override val slot: SettingsSlot = SettingsSlot.ACTIVE_SCANNER_TAB

    /** Built in [createComponent] on the EDT; the host calls no other UI member before it. */
    private lateinit var checkbox: JCheckBox

    override fun ownedKeys(): Set<String> = setOf(AutoQueuePlugin.KEY)

    override fun createComponent(context: SettingsContributionContext): JComponent {
        val box =
            JCheckBox(CHECKBOX_TEXT, context.store.getBoolean(AutoQueuePlugin.KEY) == true).apply {
                font = DesignTokens.Typography.body
                background = DesignTokens.Colors.surface
                foreground = DesignTokens.Colors.onSurface
                toolTipText = TOOLTIP
            }
        checkbox = box
        val grid = formGrid()
        addRowFull(grid, ROW_LABEL, box)
        return AccordionPanel(title = TITLE, subtitle = SUBTITLE, content = grid, initiallyExpanded = true)
    }

    override fun collect(): ContributionSnapshot = AutoQueueSnapshot(enabled = checkbox.isSelected)

    override fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    ) {
        store.setBoolean(AutoQueuePlugin.KEY, (snapshot as AutoQueueSnapshot).enabled)
    }

    override fun defaults(): ContributionSnapshot = AutoQueueSnapshot(enabled = false)

    override fun applyToUi(snapshot: ContributionSnapshot) {
        checkbox.isSelected = (snapshot as AutoQueueSnapshot).enabled
    }

    private companion object {
        // UI-SPEC C-N5 (title, subtitle, 1.0.1 row label), C-N3 (checkbox), C-N4 (tooltip).
        const val TITLE = "Auto-queue"
        const val SUBTITLE = "Off by default. Sends requests to the target when on."
        const val ROW_LABEL = "Auto-queue findings"
        const val CHECKBOX_TEXT = "Auto-queue passive findings for active testing"
        const val TOOLTIP =
            "Off by default. When on, AI passive findings are queued to the Active Scanner, which sends requests to the target."
    }
}
