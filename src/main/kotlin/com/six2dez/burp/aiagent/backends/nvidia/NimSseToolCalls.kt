package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.JsonNode
import com.six2dez.burp.aiagent.backends.FunctionCall

/** Accumulates only buffered SSE deltas; no invocation is exposed before a complete response. */
internal class NimSseToolCalls {
    private data class Parts(
        var id: String = "",
        val name: StringBuilder = StringBuilder(),
        val args: StringBuilder = StringBuilder(),
    )

    private val calls = sortedMapOf<Int, Parts>()

    fun append(delta: JsonNode) {
        if (!delta.isArray) return
        for (item in delta) {
            val index = item.path("index").asInt(-1)
            require(index in 0 until MAX_CALLS) { "Invalid streamed tool-call index" }
            val parts = calls.getOrPut(index) { Parts() }
            val id = item.path("id").asText("")
            if (id.isNotBlank() && id != parts.id) parts.id += id
            val function = item.path("function")
            val name = function.path("name").asText("")
            if (name.isNotBlank() && name != parts.name.toString()) parts.name.append(name)
            parts.args.append(function.path("arguments").asText(""))
            require(parts.id.length <= MAX_ID_CHARS && parts.name.length <= MAX_NAME_CHARS && parts.args.length <= MAX_ARG_CHARS) { "Streamed function call exceeds its decoding limit" }
        }
    }

    fun completed(): List<FunctionCall> {
        val array = NimProtocol.mapper.createArrayNode()
        for (parts in calls.values) array.add(NimProtocol.mapper.valueToTree<JsonNode>(mapOf("id" to parts.id, "type" to "function", "function" to mapOf("name" to parts.name.toString(), "arguments" to parts.args.toString()))))
        return NimNativeTools.parse(array)
    }

    companion object {
        private const val MAX_CALLS = 16
        private const val MAX_ID_CHARS = 128
        private const val MAX_NAME_CHARS = 64
        private const val MAX_ARG_CHARS = 256_000
    }
}
