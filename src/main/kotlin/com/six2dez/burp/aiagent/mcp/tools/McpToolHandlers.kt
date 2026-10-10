package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.audit.ActivityType
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server

internal fun Server.registerToolHandler(
    toolId: String,
    context: McpToolContext,
) {
    val descriptor = McpToolCatalog.available().firstOrNull { it.id == toolId } ?: return
    if (descriptor.proOnly && context.edition != burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL) {
        return
    }

    addTool(
        name = descriptor.id,
        description = descriptor.description,
        inputSchema = McpToolExecutor.inputSchema(descriptor.id, context),
        handler = { request ->
            val argsJson = request.arguments.toString().takeIf { it != "null" }
            val startMs = System.currentTimeMillis()
            val result = McpToolExecutor.executeToolResult(descriptor.id, argsJson, context)
            val durationMs = System.currentTimeMillis() - startMs
            val argsSummary = argsJson?.take(120) ?: "(none)"
            val resultText =
                result.content
                    .filterIsInstance<TextContent>()
                    .joinToString("\n") { it.text?.toString().orEmpty() }
            val argsHash = argsJson?.takeIf { it.isNotBlank() }?.let { Hashing.sha256Hex(it) } ?: ""
            val resultHash = resultText.takeIf { it.isNotBlank() }?.let { Hashing.sha256Hex(it) } ?: ""
            val policyDecision =
                when {
                    resultText.startsWith("Tool disabled:") -> "disabled"
                    resultText.startsWith("Unsafe mode is disabled for tool:") -> "unsafe_blocked"
                    resultText.startsWith("Tool requires Burp Suite Professional:") -> "pro_only"
                    resultText.startsWith("Too many concurrent MCP requests.") -> "concurrency_limited"
                    else -> "allowed"
                }
            val status =
                when {
                    policyDecision != "allowed" -> "blocked"
                    result.isError == true -> "error"
                    else -> "ok"
                }

            context.aiRequestLogger?.log(
                type = ActivityType.MCP_TOOL_CALL,
                source = "mcp",
                backendId = "mcp-server",
                detail = "Tool: ${descriptor.id} | Args: $argsSummary",
                durationMs = durationMs,
                metadata =
                    mapOf(
                        "toolId" to descriptor.id,
                        "status" to status,
                        "policyDecision" to policyDecision,
                        "durationMs" to durationMs.toString(),
                        "argsSha256" to argsHash,
                        "resultSha256" to resultHash,
                        "resultChars" to resultText.length.toString(),
                    ),
            )

            result
        },
    )
}
