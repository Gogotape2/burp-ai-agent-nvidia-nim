package com.six2dez.burp.aiagent.agents

import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Phase 31 / D-17 (TOOL-01) — keeps the store suite's generic tool list honest. On the full classpath the
 * catalog holds the native tools plus every generic tool, so [BundledProfileToolNamesTest.GENERIC_TOOL_IDS]
 * must equal the full catalog minus [BundledProfileToolNamesTest.NATIVE_IDS]. A generic tool added to (or
 * removed from) the full build without updating that list fails here, so the profile pin cannot go stale.
 */
class FullBundledProfileToolNamesTest {
    @Test
    fun genericToolIdsAreTheFullCatalogMinusTheNativeIds() {
        val catalogIds = McpToolCatalog.all().map { it.id }.toSet()

        assertEquals(
            catalogIds - BundledProfileToolNamesTest.NATIVE_IDS,
            BundledProfileToolNamesTest.GENERIC_TOOL_IDS,
            "GENERIC_TOOL_IDS drifted from the full tool catalog",
        )
        assertEquals(51, BundledProfileToolNamesTest.GENERIC_TOOL_IDS.size)
        assertEquals(
            BundledProfileToolNamesTest.NATIVE_IDS,
            catalogIds intersect BundledProfileToolNamesTest.NATIVE_IDS,
            "every native tool is in the full catalog too",
        )
    }
}
