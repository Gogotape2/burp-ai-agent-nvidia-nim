package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpToolContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement

// Phase 29 / D-13 — the argument helpers every tool handler shares, in either source set. They were
// private members of `McpToolExecutor` while every tool body lived in its dispatch `when`.

/** Default page size of a paged tool when the call names neither `count` nor `limit`. */
private const val DEFAULT_PAGE_COUNT = 5

/** Default page offset of a paged tool. */
private const val DEFAULT_PAGE_OFFSET = 0

internal val toolArgsJson = Json { ignoreUnknownKeys = true }

/**
 * Decodes a tool's JSON arguments into [T]; blank input decodes as `{}`. A missing required field
 * becomes an IllegalArgumentException that names the input type, with the serializer's exception as
 * its cause.
 */
@OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
internal inline fun <reified T : Any> decodeToolArgs(raw: String?): T {
    val jsonText = raw?.trim().orEmpty().ifBlank { "{}" }
    val element = toolArgsJson.parseToJsonElement(jsonText)
    try {
        return toolArgsJson.decodeFromJsonElement(element)
    } catch (e: kotlinx.serialization.MissingFieldException) {
        throw IllegalArgumentException(
            "Missing required argument(s) for ${T::class.simpleName}: ${e.message}. " +
                "Please provide the required fields in the JSON arguments.",
            e,
        )
    }
}

/** The arguments as a JSON object, or an empty map when they are blank, malformed or not an object. */
internal fun parseToolArgsObject(rawArgs: String?): Map<String, JsonElement> {
    val text = rawArgs?.trim().orEmpty()
    if (text.isBlank()) return emptyMap()
    return try {
        toolArgsJson.parseToJsonElement(text) as? JsonObject ?: emptyMap()
    } catch (_: Exception) {
        emptyMap()
    }
}

/** Fails the call (inside `runTool`) unless Burp is Professional. */
internal fun ensureProEdition(
    context: McpToolContext,
    name: String,
) {
    check(context.edition == BurpSuiteEdition.PROFESSIONAL) { "Tool requires Burp Suite Professional: $name" }
}

/**
 * Paging defaults for a paged tool: `count` falls back to `limit`, then to [DEFAULT_PAGE_COUNT];
 * `offset` falls back to [DEFAULT_PAGE_OFFSET]; `limit` is removed.
 */
internal fun normalizePagedArgs(rawArgs: String?): String {
    val obj = parseToolArgsObject(rawArgs)
    val count = obj["count"] ?: obj["limit"] ?: JsonPrimitive(DEFAULT_PAGE_COUNT)
    val offset = obj["offset"] ?: JsonPrimitive(DEFAULT_PAGE_OFFSET)
    val merged =
        obj.toMutableMap().apply {
            put("count", count)
            put("offset", offset)
            remove("limit")
        }
    return JsonObject(merged).toString()
}
