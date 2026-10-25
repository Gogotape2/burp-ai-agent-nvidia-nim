package com.six2dez.burp.aiagent.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal fun activeToolSchemaBounds(schema: Tool.Input): Tool.Input {
    val ranges =
        mapOf(
            "maxRequests" to (1L to ActiveToolLimits.MAX_REQUESTS.toLong()),
            "concurrency" to (1L to ActiveToolLimits.MAX_CONCURRENCY.toLong()),
            "timeoutMs" to (ActiveToolLimits.MIN_TIMEOUT_MS to ActiveToolLimits.MAX_TIMEOUT_MS),
            "durationMs" to (ActiveToolLimits.MIN_TIMEOUT_MS to ActiveToolLimits.MAX_DURATION_MS),
            "intervalMs" to (0L to ActiveToolLimits.MAX_INTERVAL_MS),
            "waitMs" to (0L to ActiveToolLimits.MAX_WAIT_MS),
            "count" to (1L to ActiveToolLimits.MAX_PAGE.toLong()),
        )
    val properties =
        schema.properties.mapValues { (name, field) ->
            val additions =
                when {
                    name in ranges -> mapOf("minimum" to JsonPrimitive(ranges.getValue(name).first), "maximum" to JsonPrimitive(ranges.getValue(name).second))
                    name in setOf("offset", "afterSequence") -> mapOf("minimum" to JsonPrimitive(0))
                    name == "positions" -> mapOf("minItems" to JsonPrimitive(1), "maxItems" to JsonPrimitive(ActiveToolLimits.MAX_POSITIONS))
                    else -> emptyMap()
                }
            JsonObject((field as JsonObject) + additions)
        }
    return Tool.Input(JsonObject(properties), schema.required)
}
