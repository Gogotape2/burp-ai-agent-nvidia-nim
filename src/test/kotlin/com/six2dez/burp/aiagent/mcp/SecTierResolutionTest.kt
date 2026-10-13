package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

/**
 * SC6: proves SEC-06 tier resolution for every shape of tool name the model can emit — a catalog ID,
 * one of the ten aliases, an `ext:` namespaced name, and three unknown-name shapes.
 *
 * No tool-context fixture appears here, and that is the point: the gate is context-free and pure, so
 * every row below is assertable with no Burp API, no mock and no Swing harness. If a future change
 * makes a context necessary, the gate has stopped being pure — fix the gate, do not import a fixture.
 *
 * Phase 29 (D-16): the catalog-ID and alias rows name generic tools and their aliases, which only the
 * full flavor packages, so they run in FullSecTierResolutionTest. The rows here hold in both builds.
 */
class SecTierResolutionTest {
    @Test
    fun externalToolNamespaceResolvesToConfirmEach() {
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor("ext:demo:anything"))
        assertEquals(
            SecTier.CONFIRM_EACH,
            ToolApprovalGate.tierFor("ext:demo:scope_check"),
            "An external tool whose name collides with a built-in must NOT inherit the built-in's " +
                "tier (T-22-03). The tier is derived from the ext: namespace, never from the catalog.",
        )
        assertNotEquals(SecTier.AUTO, ToolApprovalGate.tierFor("ext:demo:scope_check"))
    }

    @Test
    fun unknownToolFailsClosed() {
        // "EXT:demo:x" is deliberate: canonicalToolId lowercases only for MATCHING and returns the
        // original string, so the wrong-case name never matches the ext: prefix and falls through to
        // the catalog lookup — the same path the executor takes before returning "Unknown tool:".
        val unknownNames = listOf("definitely_not_a_tool", "", "EXT:demo:x")
        unknownNames.forEach { name ->
            assertEquals(
                SecTier.CONFIRM_EACH,
                ToolApprovalGate.tierFor(name),
                "Unrecognised tool name '$name' must fail closed to CONFIRM_EACH.",
            )
            assertNotEquals(
                SecTier.AUTO,
                ToolApprovalGate.tierFor(name),
                "Unrecognised tool name '$name' resolved to AUTO and would have run silently. " +
                    "D-03 removes the AUTHORING default; it does not supply a RUNTIME fallback, " +
                    "and this is that fallback.",
            )
        }
    }

    @Test
    fun everyCatalogToolResolvesThroughTheGate() {
        McpToolCatalog.all().forEach { descriptor ->
            assertEquals(
                descriptor.secTier,
                ToolApprovalGate.tierFor(descriptor.id),
                "Catalog tool '${descriptor.id}' did not resolve to its own declared tier through " +
                    "the gate.",
            )
        }
    }
}
