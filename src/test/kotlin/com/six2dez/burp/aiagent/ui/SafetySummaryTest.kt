package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.components.SafetyIndicator.Level
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 31 / D-13 / Pitfall 8 — the header safety indicator counts Unsafe only when the loaded catalog
 * has unsafe tools. With unsafe tools (the full build) every level and tooltip equals 1.0.1; without
 * them (the store build) a carried-over `unsafeEnabled = true` contributes nothing.
 */
class SafetySummaryTest {
    @Test
    fun externalPlusUnsafeIsRiskOnlyWhenUnsafeToolsExist() {
        val s = settings(mcp = true, external = true, unsafe = true)
        assertEquals(Level.RISK, SafetySummary.safetyLevel(s, hasUnsafeTools = true))
        assertEquals(
            Level.WARN,
            SafetySummary.safetyLevel(s, hasUnsafeTools = false),
            "Without unsafe tools the external flag alone decides: WARN, the external-only rule.",
        )
    }

    @Test
    fun localMcpWithUnsafeIsWarnOnlyWhenUnsafeToolsExist() {
        val s = settings(mcp = true, external = false, unsafe = true)
        assertEquals(Level.WARN, SafetySummary.safetyLevel(s, hasUnsafeTools = true))
        assertEquals(Level.OK, SafetySummary.safetyLevel(s, hasUnsafeTools = false))
    }

    @Test
    fun unsafeWithMcpOffIsWarnOnlyWhenUnsafeToolsExist() {
        val s = settings(mcp = false, external = false, unsafe = true)
        assertEquals(Level.WARN, SafetySummary.safetyLevel(s, hasUnsafeTools = true))
        assertEquals(Level.OK, SafetySummary.safetyLevel(s, hasUnsafeTools = false))
    }

    @Test
    fun privacyOffRulesAreUnchangedInBothBuilds() {
        listOf(true, false).forEach { hasUnsafe ->
            assertEquals(
                Level.RISK,
                SafetySummary.safetyLevel(settings(mcp = true, privacy = PrivacyMode.OFF), hasUnsafe),
                "Privacy OFF with MCP on is RISK (hasUnsafeTools=$hasUnsafe).",
            )
            assertEquals(
                Level.WARN,
                SafetySummary.safetyLevel(settings(mcp = false, privacy = PrivacyMode.OFF), hasUnsafe),
                "Privacy OFF alone is WARN (hasUnsafeTools=$hasUnsafe).",
            )
        }
    }

    @Test
    fun externalAloneIsWarnAndAQuietSetupIsOkInBothBuilds() {
        listOf(true, false).forEach { hasUnsafe ->
            assertEquals(Level.WARN, SafetySummary.safetyLevel(settings(mcp = true, external = true), hasUnsafe))
            assertEquals(Level.OK, SafetySummary.safetyLevel(settings(mcp = true), hasUnsafe))
            assertEquals(Level.OK, SafetySummary.safetyLevel(settings(mcp = false), hasUnsafe))
        }
    }

    /** With unsafe tools present the level equals the 1.0.1 rule for every combination of flags. */
    @Test
    fun withUnsafeToolsEveryLevelMatchesTheOneZeroOneRule() {
        // Every (mcp, external, unsafe) bit pattern crossed with every privacy mode.
        val matrix =
            (0 until 8).flatMap { bits ->
                PrivacyMode.entries.map { privacy ->
                    settings(mcp = bits and 1 != 0, external = bits and 2 != 0, unsafe = bits and 4 != 0, privacy = privacy)
                }
            }
        matrix.forEach { s ->
            assertEquals(legacyLevel(s), SafetySummary.safetyLevel(s, hasUnsafeTools = true), "Case $s")
        }
        val cases = matrix.size
        assertTrue(cases >= 24, "Anti-vacuity: the whole flag matrix ran.")
    }

    @Test
    fun theTooltipSaysUnsafeOnOnlyWhenUnsafeIsEnabledAndUnsafeToolsExist() {
        val on = settings(mcp = true, external = true, unsafe = true, passive = true)
        assertEquals(
            "<html><b>Safety</b><br>Privacy: STRICT<br>MCP: MCP external<br>Unsafe on<br>" +
                "Passive on / Active off</html>",
            SafetySummary.tooltip(on, hasUnsafeTools = true),
            "With unsafe tools the tooltip is byte-identical to 1.0.1.",
        )
        assertEquals(
            "<html><b>Safety</b><br>Privacy: STRICT<br>MCP: MCP external<br>Unsafe off<br>" +
                "Passive on / Active off</html>",
            SafetySummary.tooltip(on, hasUnsafeTools = false),
            "Without unsafe tools a carried-over true reads Unsafe off; every other line is unchanged.",
        )
        val off = settings(mcp = false, unsafe = false, active = true, privacy = PrivacyMode.BALANCED)
        listOf(true, false).forEach { hasUnsafe ->
            assertEquals(
                "<html><b>Safety</b><br>Privacy: BALANCED<br>MCP: MCP off<br>Unsafe off<br>" +
                    "Passive off / Active on</html>",
                SafetySummary.tooltip(off, hasUnsafe),
            )
        }
        val local = SafetySummary.tooltip(settings(mcp = true, unsafe = true), hasUnsafeTools = false)
        assertTrue(local.contains("MCP: MCP local<br>"), "Anti-vacuity: the local exposure line renders.")
        assertFalse(local.contains("Unsafe on"), "No Unsafe on claim without unsafe tools.")
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────

    /** MainTab.updateSafetySummary's level rule as shipped in 1.0.1, kept here as the reference. */
    private fun legacyLevel(settings: AgentSettings): Level {
        val mcp = settings.mcpSettings
        return when {
            mcp.enabled && mcp.externalEnabled && mcp.unsafeEnabled -> Level.RISK
            settings.privacyMode == PrivacyMode.OFF && mcp.enabled -> Level.RISK
            settings.privacyMode == PrivacyMode.OFF || mcp.externalEnabled || mcp.unsafeEnabled -> Level.WARN
            else -> Level.OK
        }
    }

    private fun settings(
        mcp: Boolean,
        external: Boolean = false,
        unsafe: Boolean = false,
        privacy: PrivacyMode = PrivacyMode.STRICT,
        passive: Boolean = false,
        active: Boolean = false,
    ): AgentSettings {
        val base = TestSettings.baselineSettings()
        return base.copy(
            privacyMode = privacy,
            passiveAiEnabled = passive,
            activeAiEnabled = active,
            mcpSettings =
                base.mcpSettings.copy(
                    enabled = mcp,
                    externalEnabled = external,
                    unsafeEnabled = unsafe,
                ),
        )
    }
}
