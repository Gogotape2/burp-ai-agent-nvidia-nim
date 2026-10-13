package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Phase 29 (D-16) — the generic half of [ToolRegistryTest], moved here verbatim from it.
 *
 * Both tests build a registry over the real `GenericToolProvider`, which only the full flavor
 * packages: one pins its model-facing aliases, the other pins that the core ids stay the eight native
 * tools when the generic family is loaded beside them. The store-side ToolRegistryTest keeps the
 * construction contract, which it proves with fake providers.
 */
class FullToolRegistryTest {
    @Test
    fun canonicalIdResolvesTheGenericAliasesAndPassesEverythingElseThrough() {
        val registry = ToolRegistry(listOf(NativeToolProvider(), GenericToolProvider()))
        assertEquals("proxy_http_history", registry.canonicalId("History"))
        assertEquals("site_map", registry.canonicalId(" sitemap "))
        assertEquals("proxy_ws_history", registry.canonicalId("websocket"))
        assertEquals("not_a_tool", registry.canonicalId("not_a_tool"))
        // Unmatched input comes back verbatim, case included: lowercasing is for MATCHING only.
        assertEquals("EXT:demo:x", registry.canonicalId("EXT:demo:x"))
    }

    @Test
    fun coreToolIdsAreExactlyTheEightNatives() {
        val registry = ToolRegistry(listOf(NativeToolProvider(), GenericToolProvider()))
        assertEquals(NATIVE_IDS.toSet(), registry.coreToolIds())
        assertEquals(NATIVE_IDS.toSet(), McpToolCatalog.coreToolIds())
        assertEquals(NATIVE_IDS, registry.descriptors().take(NATIVE_IDS.size).map { it.id })
    }

    private companion object {
        // Copied from ToolRegistryTest's companion, where it is private.
        val NATIVE_IDS =
            listOf(
                "status",
                "issue_create",
                "ai_analyze",
                "ai_passive_scan",
                "ai_findings_recent",
                "redact_preview",
                "ai_audit_query",
                "ai_backends_list",
            )
    }
}
