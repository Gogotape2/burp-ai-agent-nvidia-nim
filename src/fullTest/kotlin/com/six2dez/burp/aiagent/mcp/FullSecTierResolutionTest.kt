package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 29 (D-16) — the generic half of [SecTierResolutionTest], moved here verbatim from it.
 *
 * These rows resolve generic catalog IDs (`scope_check`, `proxy_http_history`, `http1_request`) and
 * the ten model-facing aliases, all declared by the generic tool provider that only the full flavor
 * packages. The store-side SecTierResolutionTest keeps the rows that hold in both builds: the `ext:`
 * namespace, unknown names failing closed, and every loaded catalog tool resolving to its own tier.
 */
class FullSecTierResolutionTest {
    /**
     * The ten alias inputs McpToolExecutor.canonicalToolId accepts, enumerated rather than sampled so
     * that adding an alias without extending this list is visible.
     */
    private val aliasInputs =
        listOf(
            "history",
            "proxy_history",
            "requests",
            "history_regex",
            "proxy_history_regex",
            "ws_history",
            "websocket_history",
            "websocket",
            "sitemap",
            "site_map_history",
        )

    /** The four canonical IDs those ten aliases collapse onto. All four are CONFIRM tools. */
    private val canonicalIds =
        setOf(
            "proxy_http_history",
            "proxy_http_history_regex",
            "proxy_ws_history",
            "site_map",
        )

    @Test
    fun builtInToolResolvesToItsCatalogTier() {
        assertEquals(SecTier.AUTO, ToolApprovalGate.tierFor("scope_check"))
        assertEquals(SecTier.CONFIRM, ToolApprovalGate.tierFor("proxy_http_history"))
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor("http1_request"))
    }

    @Test
    fun everyAliasResolvesToItsCanonicalToolsTier() {
        aliasInputs.forEach { alias ->
            assertEquals(
                SecTier.CONFIRM,
                ToolApprovalGate.tierFor(alias),
                "Alias '$alias' did not resolve to its canonical tool's tier. A gate that skips " +
                    "canonicalisation labels this call 'unknown tool' on the card and in the audit " +
                    "record while the executor runs it as a known bulk-history tool.",
            )
        }
    }

    @Test
    fun gateAndExecutorConsumeTheSameCanonicalisation() {
        aliasInputs.forEach { alias ->
            val canonical = McpToolExecutor.canonicalToolId(alias)
            assertTrue(
                canonical in canonicalIds,
                "Executor canonicalised '$alias' to '$canonical', which is not one of the four " +
                    "canonical IDs this test knows about.",
            )
            val descriptor = McpToolCatalog.all().first { it.id == canonical }
            assertEquals(
                descriptor.secTier,
                ToolApprovalGate.tierFor(alias),
                "The gate and the executor disagree about '$alias'. Either side growing its own " +
                    "alias handling is the defect this assertion exists to catch — there must be " +
                    "exactly one canonicalisation function and both sides must call it.",
            )
        }
    }
}
