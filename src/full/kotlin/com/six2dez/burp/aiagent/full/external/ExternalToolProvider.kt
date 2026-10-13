package com.six2dez.burp.aiagent.full.external

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager
import com.six2dez.burp.aiagent.mcp.tools.ToolSpec
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull

/**
 * Phase 29 / NET-02, D-14 — the full build's `ext:<server>:<tool>` namespace, as a [ToolProvider]'s
 * dynamic namespace (listed in `src/full`'s `META-INF/services/com.six2dez.burp.aiagent.spi.ToolProvider`).
 * The store build has neither this class nor the external MCP client, so its executor answers every
 * `ext:` name with "Unknown tool".
 *
 * The routing moved here from the 1.0.1 executor (`routeExternalToolCall`) with its behavior and error
 * texts unchanged:
 * - the name must split into `ext:<server>:<tool>`, else "Invalid external tool name ...";
 * - with no manager the result is "External MCP client not available";
 * - D-03 outbound privacy: the arguments pass through [McpToolContext.redactIfNeeded] before they are
 *   forwarded to the third-party server;
 * - SC2 / T-16-04-PI: the trust-boundary wrap is applied by [ExternalMcpClientManager.callTool], and the
 *   wrapped text is returned unchanged.
 *
 * The approval tier is not this provider's to decide: `ToolApprovalGate` derives CONFIRM_EACH from the
 * `ext:` prefix in both builds (ADR-11, T-29-30).
 *
 * Production has no manager wired, exactly as 1.0.1 (parity, not scope creep), so [managerSource] defaults
 * to none and the all-default constructor is the no-arg constructor ServiceLoader needs. Tests pass a fake.
 */
class ExternalToolProvider(
    private val managerSource: () -> ExternalMcpClientManager? = { null },
) : ToolProvider {
    /** The namespace has no static tools: nothing here enters the catalog or inherits a catalog tier. */
    override fun handlers(): List<ToolHandler> = emptyList()

    override fun resolveDynamic(
        canonicalId: String,
        args: String?,
        context: McpToolContext,
    ): CallToolResult? = if (canonicalId.startsWith(PREFIX)) route(canonicalId, args, context) else null

    override fun describeDynamic(context: McpToolContext): List<ToolSpec> =
        managerSource()
            ?.availableTools()
            ?.map { ext ->
                ToolSpec(
                    id = ext.name,
                    description = ext.description,
                    enabled = true,
                    unsafeOnly = false,
                    proOnly = false,
                    argsSchema = null,
                )
            }.orEmpty()

    override fun isDynamicTool(
        canonicalId: String,
        context: McpToolContext,
    ): Boolean =
        managerSource()
            ?.availableTools()
            .orEmpty()
            .any { it.name == canonicalId }

    /**
     * `TooGenericExceptionCaught`: any failure of the remote call becomes an error result naming the
     * server and tool, as in 1.0.1. `ReturnCount`: the three early returns are the three 1.0.1 error texts.
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    private fun route(
        name: String,
        argsJson: String?,
        context: McpToolContext,
    ): CallToolResult {
        val parts = name.split(":", limit = EXT_TOOL_NAME_PARTS)
        if (parts.size < EXT_TOOL_NAME_PARTS) {
            return errorResult("Invalid external tool name (expected ext:<server>:<tool>): $name")
        }
        val serverName = parts[1]
        val remoteName = parts[2]

        val manager = managerSource() ?: return errorResult("External MCP client not available")

        // D-03 (outbound privacy): redact args before sending to the third-party external server.
        val redactedArgs = context.redactIfNeeded(argsJson.orEmpty())
        val argsMap = parseArgsMapOrEmpty(redactedArgs)

        return try {
            val resultText = runBlocking { manager.callTool(serverName, remoteName, argsMap) }
            // Trust-boundary wrap is already in resultText (Plan 16-03) — preserve as-is.
            CallToolResult(content = listOf(TextContent(resultText)), isError = false)
        } catch (e: Exception) {
            errorResult("External tool call failed ($serverName/$remoteName): ${e.message.orEmpty()}")
        }
    }

    companion object {
        private const val PREFIX = "ext:"

        // Phase 16 (CAP-02): expected part count for ext:<server>:<tool> tool names.
        private const val EXT_TOOL_NAME_PARTS = 3

        private val decodeJson = Json { ignoreUnknownKeys = true }

        private fun errorResult(message: String): CallToolResult = CallToolResult(content = listOf(TextContent(message)), isError = true)

        /**
         * Parses a JSON string into `Map<String, Any?>` for forwarding to an external MCP server, the
         * `args` map [ExternalMcpClientManager.callTool] accepts. Returns [emptyMap] on blank input or a
         * parse failure (safe degradation). Moved unchanged from the 1.0.1 executor.
         */
        @Suppress("UNCHECKED_CAST", "ReturnCount", "TooGenericExceptionCaught", "SwallowedException")
        internal fun parseArgsMapOrEmpty(json: String): Map<String, Any?> {
            val text = json.trim()
            if (text.isBlank() || text == "{}") return emptyMap()
            return try {
                val element = decodeJson.parseToJsonElement(text)
                val obj = element as? JsonObject ?: return emptyMap()
                // Convert JsonObject entries to Map<String, Any?> via kotlinx-serialization primitives.
                // The MCP SDK callTool() accepts Any? values; primitives coerce cleanly.
                obj.entries.associate { (k, v) ->
                    k to
                        when (v) {
                            is JsonPrimitive ->
                                when {
                                    v.isString -> v.content
                                    v.booleanOrNull != null -> v.boolean
                                    v.content.toLongOrNull() != null -> v.content.toLong()
                                    v.content.toDoubleOrNull() != null -> v.content.toDouble()
                                    else -> v.content
                                }
                            else -> v.toString()
                        }
                }
            } catch (_: Exception) {
                emptyMap()
            }
        }
    }
}
