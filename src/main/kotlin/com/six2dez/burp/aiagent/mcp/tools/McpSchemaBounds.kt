package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Advertise the same request limits that execution enforces, including project-specific history caps. */
internal fun boundedToolSchema(
    name: String,
    schema: Tool.Input,
    context: McpToolContext?,
): Tool.Input {
    if (name in ActiveToolHandlers.ids) return activeToolSchemaBounds(schema)
    val properties = schema.properties.toMutableMap()
    val paged = setOf("proxy_http_history", "proxy_http_history_regex", "response_body_search", "proxy_ws_history", "proxy_ws_history_regex", "site_map", "site_map_regex", "scanner_issues")
    val bounds =
        when {
            name in setOf("proxy_http_history", "proxy_http_history_regex") -> context?.proxyHistoryMaxItemsPerRequest ?: MAX_SCHEMA_ITEMS
            name in paged -> MAX_SCHEMA_ITEMS
            name == "context_read" -> com.six2dez.burp.aiagent.context.ChatContextStore.MAX_CHUNK_CHARS
            else -> null
        }
    if (bounds != null) properties["count"]?.let { properties["count"] = numericBounds(it as JsonObject, 1, bounds.toLong()) }
    properties["offset"]?.let { properties["offset"] = JsonObject((it as JsonObject) + ("minimum" to JsonPrimitive(0))) }
    properties["timeoutMs"]?.let { properties["timeoutMs"] = numericBounds(it as JsonObject, MIN_REQUEST_TIMEOUT_MS, MAX_REQUEST_TIMEOUT_MS) }
    return Tool.Input(properties = JsonObject(properties), required = schema.required)
}

private const val MAX_SCHEMA_ITEMS = 1000
private const val MIN_REQUEST_TIMEOUT_MS = 1000L
private const val MAX_REQUEST_TIMEOUT_MS = 600_000L

private fun numericBounds(
    schema: JsonObject,
    minimum: Long,
    maximum: Long,
): JsonObject = JsonObject(schema + mapOf("minimum" to JsonPrimitive(minimum), "maximum" to JsonPrimitive(maximum)))
