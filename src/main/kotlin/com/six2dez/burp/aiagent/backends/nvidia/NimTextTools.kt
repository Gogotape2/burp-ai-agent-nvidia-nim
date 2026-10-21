package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.FunctionCall

/** Accept complete tool-only turns; never extract executable examples from prose. */
internal object NimTextTools {
    private const val MAX_CHARS = 1_000_000
    private const val MAX_CALLS = 16
    private val mapper = NimProtocol.mapper.copy().disable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
    private val fence = Regex("\\A```(?:json|tool)\\s*([\\s\\S]*?)\\s*```\\z", RegexOption.IGNORE_CASE)
    private val argsKeys = setOf("args", "arguments", "input")
    private val allowedKeys = argsKeys + setOf("tool", "name", "id", "type")

    fun recover(
        completion: NimProtocol.Completion,
        request: AgentChatRequest,
        native: Boolean,
        event: (AgentTurnEvent) -> Unit,
    ): NimProtocol.Completion {
        val enabled = completion.calls.isEmpty() && !request.jsonMode && request.tools.isNotEmpty()
        val calls = if (enabled) parse(completion.content) else null
        return if (calls == null) {
            completion
        } else {
            val allowed = request.tools.map { it.name }.toSet()
            require(calls.all { it.name in allowed }) { "NVIDIA NIM requested an unavailable text function; the entire batch was not executed" }
            event(AgentTurnEvent("text_tools", "Recovered ${calls.size} complete text function call(s); ${if (native) "native" else "text"} results will be correlated"))
            completion.copy(content = "", calls = calls)
        }
    }

    fun parse(text: String): List<FunctionCall>? {
        val candidate = unwrap(text)
        val eligible = candidate.length <= MAX_CHARS && candidate.firstOrNull() in listOf('{', '[')
        val objects = if (eligible) readAll(candidate) else null
        val wrapped = objects?.let { nativeWrapper(it) }
        return when {
            objects.isNullOrEmpty() -> null
            wrapped != null -> NimNativeTools.parse(wrapped).takeIf { it.isNotEmpty() }
            objects.any { !callShape(it) } -> null
            else -> {
                require(objects.size <= MAX_CALLS) { "Text function batch exceeds the 16-call limit; no calls were executed" }
                NimNativeTools.parse(mapper.valueToTree(objects.map { wireCall(it) }))
            }
        }
    }

    private fun unwrap(text: String): String {
        val trimmed = text.trim()
        return fence
            .matchEntire(trimmed)
            ?.groupValues
            ?.get(1)
            ?.trim() ?: trimmed
    }

    private fun nativeWrapper(objects: List<JsonNode>): JsonNode? =
        objects
            .singleOrNull()
            ?.takeIf { node ->
                val singleObject = node.isObject && node.size() == 1
                singleObject && node.has("tool_calls")
            }?.path("tool_calls")

    private fun wireCall(node: JsonNode): Map<String, Any> {
        val name = node.path("tool").takeIf { it.isTextual }?.asText() ?: node.path("name").asText()
        val args = argsKeys.firstNotNullOfOrNull { node.get(it) }
        val encoded =
            when {
                args == null || args.isNull -> "{}"
                args.isTextual -> args.asText()
                else -> mapper.writeValueAsString(args)
            }
        return mapOf("type" to "function", "function" to mapOf("name" to name, "arguments" to encoded))
    }

    private fun callShape(node: JsonNode): Boolean =
        node.isObject &&
            node.properties().map { it.key }.all { it in allowedKeys } &&
            (!node.has("type") || node.path("type").asText() == "function") &&
            (node.path("tool").isTextual || node.path("name").isTextual && argsKeys.any { node.has(it) })

    private fun readAll(text: String): List<JsonNode>? =
        runCatching {
            val values = mutableListOf<JsonNode>()
            mapper.factory.createParser(text).use { parser ->
                while (parser.nextToken() != null) {
                    val root = mapper.readTree<JsonNode>(parser)
                    if (root.isArray) values.addAll(root.toList()) else values.add(root)
                    if (values.size > MAX_CALLS) break
                }
                // Check the whole turn before any member can be exposed to the execution gate.
                check(parser.nextToken() == null) { "Trailing data after text function batch" }
            }
            values
        }.getOrNull()
}
