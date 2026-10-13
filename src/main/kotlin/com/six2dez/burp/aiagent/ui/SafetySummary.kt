package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.components.SafetyIndicator

/**
 * The header safety indicator's level and tooltip, computed from the applied settings snapshot. Pure, so
 * the RISK / WARN / OK matrix is testable without building MainTab.
 */
internal object SafetySummary {
    fun safetyLevel(
        settings: AgentSettings,
        @Suppress("UNUSED_PARAMETER") hasUnsafeTools: Boolean,
    ): SafetyIndicator.Level {
        val mcp = settings.mcpSettings
        return when {
            mcp.enabled && mcp.externalEnabled && mcp.unsafeEnabled -> SafetyIndicator.Level.RISK
            settings.privacyMode == PrivacyMode.OFF && mcp.enabled -> SafetyIndicator.Level.RISK
            settings.privacyMode == PrivacyMode.OFF || mcp.externalEnabled || mcp.unsafeEnabled ->
                SafetyIndicator.Level.WARN
            else -> SafetyIndicator.Level.OK
        }
    }

    fun tooltip(
        settings: AgentSettings,
        @Suppress("UNUSED_PARAMETER") hasUnsafeTools: Boolean,
    ): String {
        val privacy = settings.privacyMode.name
        val mcpExposure =
            when {
                !settings.mcpSettings.enabled -> "MCP off"
                settings.mcpSettings.externalEnabled -> "MCP external"
                else -> "MCP local"
            }
        val unsafe = if (settings.mcpSettings.unsafeEnabled) "Unsafe on" else "Unsafe off"
        val scanners = "Passive ${if (settings.passiveAiEnabled) "on" else "off"} / Active ${if (settings.activeAiEnabled) "on" else "off"}"
        // HTML tooltip so the four flags wrap onto separate lines instead of one long string.
        return "<html><b>Safety</b><br>" +
            "Privacy: $privacy<br>" +
            "MCP: $mcpExposure<br>" +
            unsafe +
            "<br>" +
            scanners +
            "</html>"
    }
}
