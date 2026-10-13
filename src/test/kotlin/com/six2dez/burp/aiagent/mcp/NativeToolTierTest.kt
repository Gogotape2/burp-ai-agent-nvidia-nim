package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.NativeToolProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Phase 29 plan 29-11 (D-14) — the trust tier of each of the 8 native tools, written as literals.
 *
 * The native tools are the whole MCP catalog of the store build, so their tiers decide which tool calls
 * run without asking. The values were read from NativeTools.kt when the generic tools left the store
 * build; they are literals here on purpose, so changing a native tool's tier is a reviewed diff in two
 * files rather than a silent edit in one. The full build keeps the same tiers for these ids
 * (McpToolCatalogTierParityTest in src/fullTest pins all 59).
 */
class NativeToolTierTest {
    @Test
    fun eachNativeToolHasItsPinnedTier() {
        val actual = NativeToolProvider().handlers().associate { it.descriptor.id to it.descriptor.secTier }
        assertEquals(EXPECTED_TIERS, actual)
    }

    @Test
    fun storeCatalogReportsTheSameTiersAsTheNativeProvider() {
        val catalog = McpToolCatalog.all().associate { it.id to it.secTier }
        assertEquals(EXPECTED_TIERS, catalog)
        EXPECTED_TIERS.forEach { (id, tier) ->
            assertEquals(tier, ToolApprovalGate.tierFor(id), "ToolApprovalGate must resolve $id to its declared tier")
        }
    }

    private companion object {
        val EXPECTED_TIERS: Map<String, SecTier> =
            mapOf(
                "status" to SecTier.AUTO,
                "issue_create" to SecTier.CONFIRM,
                "ai_analyze" to SecTier.CONFIRM_EACH,
                "ai_passive_scan" to SecTier.CONFIRM_EACH,
                "ai_findings_recent" to SecTier.CONFIRM,
                "redact_preview" to SecTier.AUTO,
                "ai_audit_query" to SecTier.CONFIRM,
                "ai_backends_list" to SecTier.AUTO,
            )
    }
}
