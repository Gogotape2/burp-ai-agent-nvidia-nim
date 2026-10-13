package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.server.Server

/**
 * Registers every tool the context's registry holds on the MCP server (Phase 29 / D-14: the group
 * lists that used to live here moved into their providers). [registerToolHandler] still applies the
 * catalog's availability and edition filters and owns the audit logging.
 */
@Suppress("UNUSED_PARAMETER")
fun Server.registerTools(
    api: MontoyaApi,
    context: McpToolContext,
) {
    context.toolRegistry.descriptors().forEach { registerToolHandler(it.id, context) }
}
