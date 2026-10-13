package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.agents.BundledProfileToolNamesTest.Companion.GENERIC_TOOL_IDS
import com.six2dez.burp.aiagent.agents.BundledProfileToolNamesTest.Companion.NATIVE_IDS
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 31 / TOOL-01 (ROADMAP SC4, T-31-27) — with Unsafe switched on and every generic tool id toggled
 * on and listed as an enabled unsafe tool, every chat tool surface of the store build still sees exactly
 * the native tools: the Tools menu and the tool dialog (through [ChatToolSurface]), the tool preamble
 * ([McpToolExecutor.describeTools]) and tiering ([ToolApprovalGate.tierFor]). A generic name fails closed
 * at the executor, not merely in the UI.
 */
class StoreToolSurfaceTest {
    @Test
    fun menuAndDialogOfferExactlyTheNativeToolsWithUnsafeOn() {
        val context = unsafeOnContext()

        assertEquals(NATIVE_IDS, ChatToolSurface.menuTools().map { it.id }.toSet(), "Tools menu")
        assertEquals(NATIVE_IDS.size, ChatToolSurface.menuTools().size, "no tool may appear twice in the menu")
        assertEquals(NATIVE_IDS, ChatToolSurface.offeredChatTools(context).map { it.id }.toSet(), "tool dialog")
    }

    @Test
    fun offeredToolsKeepTheCatalogOrder() {
        val context = unsafeOnContext()
        val catalogOrder = McpToolCatalog.available().map { it.id }

        assertEquals(catalogOrder, ChatToolSurface.menuTools().map { it.id }, "menuTools order")
        assertEquals(catalogOrder, ChatToolSurface.offeredChatTools(context).map { it.id }, "offeredChatTools order")
    }

    @Test
    fun preambleListsExactlyTheNativeToolsWithUnsafeOn() {
        assertEquals(NATIVE_IDS, preambleIds(unsafeOnContext()))
    }

    @Test
    fun genericIdsResolveToTheFailClosedTierAndAreUnknownToTheExecutor() {
        val context = unsafeOnContext()
        GENERIC_TOOL_IDS.forEach { id ->
            assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor(id), "tier of $id")
        }
        listOf("http1_request", "intruder", "user_options_set").forEach { id ->
            assertUnknownTool(id, context)
        }
    }

    @Test
    fun lookupIsExactSoAdjacentNamesAreUnknown() {
        val context = unsafeOnContext()
        listOf("ai_analyze_extra", "xstatus").forEach { id ->
            assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor(id), "tier of $id")
            assertUnknownTool(id, context)
        }
    }

    @Test
    fun everyToggleOffOffersNoTool() {
        val allOff = unsafeOnContext().copy(toolToggles = (NATIVE_IDS + GENERIC_TOOL_IDS).associateWith { false })

        assertEquals(emptyList<String>(), ChatToolSurface.offeredChatTools(allOff).map { it.id })
        assertEquals(NATIVE_IDS, ChatToolSurface.menuTools().map { it.id }.toSet(), "the menu still lists the tools, disabled")
        assertTrue(ChatToolSurface.menuTools().none { ChatToolSurface.canRun(it, allOff) }, "every menu item is disabled")
    }

    @Test
    fun flippingUnsafeRepeatedlyLeavesTheSameNativeSet() {
        var context = unsafeOnContext()
        repeat(3) {
            context = context.copy(unsafeEnabled = false)
            assertSurfacesAreNative(context)
            context = context.copy(unsafeEnabled = true)
            assertSurfacesAreNative(context)
        }
    }

    private fun assertSurfacesAreNative(context: McpToolContext) {
        val label = "unsafeEnabled=${context.unsafeEnabled}"
        assertEquals(NATIVE_IDS, ChatToolSurface.menuTools().map { it.id }.toSet(), "menu, $label")
        assertEquals(NATIVE_IDS, ChatToolSurface.offeredChatTools(context).map { it.id }.toSet(), "dialog, $label")
        assertEquals(NATIVE_IDS, preambleIds(context), "preamble, $label")
        GENERIC_TOOL_IDS.forEach { assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor(it), "tier of $it, $label") }
    }

    private fun preambleIds(context: McpToolContext): Set<String> {
        val preamble = McpToolExecutor.describeTools(context, includeSchemas = false, includeDisabled = false)
        val listed =
            preamble
                .lines()
                .filter { it.startsWith("- ") }
                .map { it.removePrefix("- ").substringBefore(":") }
        assertEquals(listed.size, listed.toSet().size, "no tool may appear twice in the preamble:\n$preamble")
        return listed.toSet()
    }

    private fun assertUnknownTool(
        id: String,
        context: McpToolContext,
    ) {
        val result = McpToolExecutor.executeToolResult(id, "{}", context)
        assertEquals(true, result.isError, "$id must be rejected in the store build")
        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
        assertTrue(text.startsWith("Unknown tool: $id"), "got: $text")
    }

    /** Built like StoreFlavorSeamsTest's store context, with Unsafe on and every generic id switched on. */
    private fun unsafeOnContext(): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = (NATIVE_IDS + GENERIC_TOOL_IDS).associateWith { true },
            unsafeEnabled = true,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = GENERIC_TOOL_IDS,
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
        )
    }
}
