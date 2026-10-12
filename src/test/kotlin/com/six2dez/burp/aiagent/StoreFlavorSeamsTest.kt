package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 plan 29-11 (BUILD-01 empty-provider edge, D-14, D-16) — what the store classpath offers, pinned.
 *
 * Since plan 29-11 the generic MCP tools, their helpers and the scanner / collaborator registries are
 * compiled only from `src/full`, and the `ToolProvider` services file lives in `src/full/resources`. On
 * the store classpath (`src/main` + `src/test`, the input of the BApp Store JAR) the tool catalog is
 * therefore exactly the 8 native tools, and every seam falls back to its core default.
 *
 * This replaces `McpToolCatalogStoreBuildTest`, which plan 29-08 removed together with the store-build
 * filter. FullFlavorSeamsTest (src/fullTest) pins the full classpath side.
 *
 * T-29-22: a prompt-injected generic tool name in the store build is not an alias, is not in the catalog,
 * resolves to the fail-closed CONFIRM_EACH tier, and the executor answers "Unknown tool".
 */
class StoreFlavorSeamsTest {
    @Test
    fun storeCatalogIsExactlyTheEightNativeTools() {
        val ids = McpToolCatalog.all().map { it.id }
        assertEquals(NATIVE_IDS, ids.toSet(), "store catalog must be exactly the native tools")
        assertEquals(NATIVE_IDS.size, ids.size, "no tool id may appear twice: $ids")
        assertEquals(NATIVE_IDS, McpToolCatalog.coreToolIds(), "every store tool is a core tool")
    }

    @Test
    fun storeClasspathHasNoToolProvider() {
        assertTrue(
            Plugins.load(ToolProvider::class.java).isEmpty(),
            "the ToolProvider services file must not be on the store classpath",
        )
    }

    @Test
    fun storeClasspathHasNoExtensionPlugin() {
        assertTrue(
            Plugins.load(ExtensionPlugin::class.java).isEmpty(),
            "the ExtensionPlugin services file must not be on the store classpath (no passive-to-active auto-queue)",
        )
    }

    /**
     * Plan 29-16 / D-02, T-29-33: the passive scanner offers suggested targets only to an optional
     * SuggestedTargetSink, so it must hold no reference through which it could queue target traffic.
     */
    @Test
    fun passiveScannerDeclaresNoActiveScannerField() {
        val activeTyped =
            generateSequence<Class<*>>(PassiveAiScanner::class.java) { it.superclass }
                .flatMap { it.declaredFields.asSequence() }
                .filter { ActiveAiScanner::class.java.isAssignableFrom(it.type) }
                .map { "${it.declaringClass.simpleName}.${it.name}" }
                .toList()
        assertEquals(emptyList<String>(), activeTyped, "PassiveAiScanner fields typed ActiveAiScanner")
    }

    @Test
    fun storeClasspathResolvesTheCoreDefaults() {
        val profile = resolveFlavorProfile()
        val policy = resolveAiAccessPolicy()
        assertTrue(profile is StoreFlavorProfile, "got ${profile.javaClass.name}")
        assertTrue(policy is StoreAiAccessPolicy, "got ${policy.javaClass.name}")
    }

    @Test
    fun describeToolsListsExactlyTheEightNativeIds() {
        val preamble = McpToolExecutor.describeTools(storeContext(), includeSchemas = false)
        val listed =
            preamble
                .lines()
                .filter { it.startsWith("- ") }
                .map { it.removePrefix("- ").substringBefore(":") }
        assertEquals(NATIVE_IDS, listed.toSet(), "describeTools must list exactly the native tools:\n$preamble")
        assertEquals(NATIVE_IDS.size, listed.size)
        assertFalse(GENERIC_ID in preamble, "no generic tool may be described in the store build")
    }

    @Test
    fun genericNamesAreUnknownAndFailClosedInTheStoreBuild() {
        assertEquals("history", McpToolExecutor.canonicalToolId("history"), "the generic alias table is absent")
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor(GENERIC_ID))
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor("history"))

        val result = McpToolExecutor.executeToolResult(GENERIC_ID, "{}", storeContext())
        assertEquals(true, result.isError, "a generic tool name must be rejected in the store build")
        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
        assertTrue(text.startsWith("Unknown tool: $GENERIC_ID"), "got: $text")
    }

    private fun storeContext(): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
        )
    }

    private companion object {
        val NATIVE_IDS =
            setOf(
                "status",
                "issue_create",
                "ai_analyze",
                "ai_passive_scan",
                "ai_findings_recent",
                "redact_preview",
                "ai_audit_query",
                "ai_backends_list",
            )

        /** A generic tool of the full build (GenericHistoryTools), and the target of the "history" alias there. */
        const val GENERIC_ID = "proxy_http_history"
    }
}
