package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Apply line-based header rules before JSON escapes CR/LF in captured HTTP or WebSocket text. */
internal fun redactActiveToolResult(
    value: JsonElement,
    context: McpToolContext,
): JsonElement =
    when (value) {
        is JsonObject -> JsonObject(value.mapValues { redactActiveToolResult(it.value, context) })
        is JsonArray -> JsonArray(value.map { redactActiveToolResult(it, context) })
        is JsonPrimitive -> if (value.isString) JsonPrimitive(context.redactIfNeeded(value.content)) else value
    }
