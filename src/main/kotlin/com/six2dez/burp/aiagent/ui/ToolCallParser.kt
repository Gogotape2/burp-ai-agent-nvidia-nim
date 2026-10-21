package com.six2dez.burp.aiagent.ui

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal data class ParsedToolCall(
    val tool: String,
    val argsJson: String?,
    val invocationId: String? = null,
)

internal object ToolCallParser {
    private val toolFence = Regex("\\A```(?:tool|json)\\s*([\\s\\S]*?)\\s*```\\z", RegexOption.IGNORE_CASE)
    private val argumentKeys = setOf("args", "arguments", "input")
    private val directKeys = argumentKeys + setOf("tool", "name", "id", "type")
    private val functionKeys = setOf("function", "function_call", "id", "type")

    fun extractFirst(text: String): ParsedToolCall? {
        val trimmed = text.trim()
        // The entire assistant turn must be a call. JSON examples inside a report are data.
        val candidate =
            toolFence
                .matchEntire(trimmed)
                ?.groupValues
                ?.get(1)
                ?.trim() ?: trimmed
        return parseToolJson(candidate)
    }

    private fun parseToolJson(jsonText: String): ParsedToolCall? {
        val rootObject =
            runCatching {
                Json.parseToJsonElement(jsonText).jsonObject
            }.getOrNull() ?: return null
        return parseToolCallObject(rootObject)
    }

    private fun parseToolCallObject(obj: JsonObject): ParsedToolCall? {
        val direct = buildToolCall(obj)
        if (direct != null) return direct
        val nested = firstNestedToolCallObject(obj) ?: return null
        return buildToolCall(nested)
    }

    private fun buildToolCall(obj: JsonObject): ParsedToolCall? {
        val explicitFunction = "function" in obj || "function_call" in obj
        val explicitTool = obj["tool"].asStringOrNull()?.isNotBlank() == true
        val legacyName = obj["name"].asStringOrNull()?.isNotBlank() == true && argumentKeys.any { it in obj }
        val allowedKeys = if (explicitFunction) functionKeys else directKeys
        val callShape = explicitFunction || explicitTool || legacyName
        if (!callShape || !obj.keys.all { it in allowedKeys }) return null
        return resolveToolName(obj)?.let { ParsedToolCall(tool = it, argsJson = resolveToolArgs(obj)) }
    }

    private fun firstNestedToolCallObject(obj: JsonObject): JsonObject? {
        firstToolCallObject(obj["tool_calls"].asArrayOrNull())?.let { return it }

        val messageObj = obj["message"].asObjectOrNull()
        firstToolCallObject(messageObj?.get("tool_calls").asArrayOrNull())?.let { return it }

        val responseObj = obj["response"].asObjectOrNull()
        firstToolCallObject(responseObj?.get("tool_calls").asArrayOrNull())?.let { return it }

        val firstChoice =
            obj["choices"]
                .asArrayOrNull()
                ?.firstOrNull()
                .asObjectOrNull()
        if (firstChoice != null) {
            firstToolCallObject(firstChoice["tool_calls"].asArrayOrNull())?.let { return it }
            val choiceMessage = firstChoice["message"].asObjectOrNull()
            firstToolCallObject(choiceMessage?.get("tool_calls").asArrayOrNull())?.let { return it }
        }
        return null
    }

    private fun firstToolCallObject(array: JsonArray?): JsonObject? = array?.firstOrNull().asObjectOrNull()

    private fun resolveToolName(obj: JsonObject): String? {
        val directTool = obj["tool"].asStringOrNull()?.trim()
        if (!directTool.isNullOrBlank()) return directTool

        val directName = obj["name"].asStringOrNull()?.trim()
        if (!directName.isNullOrBlank()) return directName

        val functionName =
            obj["function"]
                .asObjectOrNull()
                ?.get("name")
                .asStringOrNull()
                ?.trim()
        if (!functionName.isNullOrBlank()) return functionName

        val functionCallName =
            obj["function_call"]
                .asObjectOrNull()
                ?.get("name")
                .asStringOrNull()
                ?.trim()
        if (!functionCallName.isNullOrBlank()) return functionCallName

        return null
    }

    private fun resolveToolArgs(obj: JsonObject): String? {
        val directArgs = obj["args"]
        if (directArgs != null) return normalizeArgsJson(directArgs)

        val arguments = obj["arguments"]
        if (arguments != null) return normalizeArgsJson(arguments)

        val input = obj["input"]
        if (input != null) return normalizeArgsJson(input)

        val functionArgs =
            obj["function"]
                .asObjectOrNull()
                ?.get("arguments")
        if (functionArgs != null) return normalizeArgsJson(functionArgs)

        val functionCallArgs =
            obj["function_call"]
                .asObjectOrNull()
                ?.get("arguments")
        return normalizeArgsJson(functionCallArgs)
    }

    private fun normalizeArgsJson(value: JsonElement?): String? {
        if (value == null) return null
        val primitive = runCatching { value.jsonPrimitive }.getOrNull()
        if (primitive != null && primitive.isString) {
            val raw = primitive.contentOrNull?.trim().orEmpty()
            return raw.ifBlank { null }
        }
        return value.toString()
    }

    private fun JsonElement?.asObjectOrNull(): JsonObject? = runCatching { this?.jsonObject }.getOrNull()

    private fun JsonElement?.asArrayOrNull(): JsonArray? = runCatching { this?.jsonArray }.getOrNull()

    private fun JsonElement?.asStringOrNull(): String? = runCatching { this?.jsonPrimitive?.takeIf { it.isString }?.contentOrNull }.getOrNull()
}
