package com.six2dez.burp.aiagent.ui

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor

/**
 * Phase 31 / TOOL-01 — the one place the chat Tools menu and the tool dialog get their tools.
 *
 * It reads [McpToolCatalog.available], so the store build offers the native tools only, and the
 * Unsafe switch cannot add a tool the catalog does not hold: Unsafe only widens [canRun] over tools
 * that are already listed. The menu and the dialog both call this object, so the two surfaces cannot
 * drift apart. Order is the catalog's (registry order, native provider first).
 */
internal object ChatToolSurface {
    /** Every tool this build offers, in catalog order. The Tools menu lists these, runnable or not. */
    fun menuTools(): List<McpToolDescriptor> = McpToolCatalog.available()

    /** Whether [tool] may run now: toggled on, allowed by the Unsafe settings, and not Pro-only on Community. */
    fun canRun(
        tool: McpToolDescriptor,
        context: McpToolContext,
    ): Boolean =
        context.isToolEnabled(tool.id) &&
            context.isUnsafeToolAllowed(tool.id) &&
            (!tool.proOnly || context.edition == BurpSuiteEdition.PROFESSIONAL)

    /** The tools the tool dialog offers: the runnable subset of [menuTools], in the same order. */
    fun offeredChatTools(context: McpToolContext): List<McpToolDescriptor> = menuTools().filter { canRun(it, context) }
}
