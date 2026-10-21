package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.ui.design.DesignTokens
import com.six2dez.burp.aiagent.ui.design.helpLabel
import com.six2dez.burp.aiagent.ui.design.sectionPanel
import java.awt.BorderLayout
import javax.swing.JCheckBox
import javax.swing.JPanel

/** The master switch writes the existing tool toggles; there is no second permission setting. */
internal object WebResearchControls {
    fun build(boxes: Map<String, JCheckBox>): JPanel {
        val tools = listOfNotNull(boxes["web_search"], boxes["web_fetch"])
        val enabled = JCheckBox("Enable free web search and page reading", tools.size == 2 && tools.all { it.isSelected })
        enabled.name = "webResearchEnabled"
        enabled.font = DesignTokens.Typography.body
        var changing = false
        enabled.addItemListener {
            if (!changing) {
                changing = true
                tools.forEach { it.isSelected = enabled.isSelected }
                changing = false
            }
        }
        tools.forEach { tool ->
            tool.addItemListener {
                if (!changing) {
                    changing = true
                    enabled.isSelected = tools.all { it.isSelected }
                    changing = false
                }
            }
        }
        val content =
            JPanel(BorderLayout()).apply {
                isOpaque = false
                add(enabled, BorderLayout.NORTH)
                add(
                    JPanel().apply {
                        isOpaque = false
                        layout = javax.swing.BoxLayout(this, javax.swing.BoxLayout.Y_AXIS)
                        add(helpLabel("DuckDuckGo • no API key • public documentation only."))
                        add(helpLabel("Save, then start a new chat. Existing tool confirmations apply."))
                    },
                    BorderLayout.CENTER,
                )
            }
        return sectionPanel("Web research", "Search public sources when current information is needed.", content)
    }
}
