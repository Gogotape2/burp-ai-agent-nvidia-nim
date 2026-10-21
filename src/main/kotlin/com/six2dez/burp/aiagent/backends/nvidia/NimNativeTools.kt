package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.JsonNode
import com.six2dez.burp.aiagent.backends.FunctionCall
import com.six2dez.burp.aiagent.backends.FunctionTool
import com.six2dez.burp.aiagent.backends.http.TransportResponse

internal object NimNativeTools {
    private val functionName = Regex("[A-Za-z_][A-Za-z0-9_-]{0,63}")
    private val callId = Regex("[A-Za-z0-9_.:-]{1,128}")
    private const val MAX_CALLS = 16
    private const val MAX_ARGUMENT_CHARS = 256_000

    fun definitions(tools: List<FunctionTool>): List<Map<String, Any>> =
        tools.map { tool ->
            require(functionName.matches(tool.name)) { "Invalid native function name" }
            val schema = NimProtocol.mapper.readTree(tool.parametersJson)
            require(schema.isObject) { "Function parameters must be an object schema" }
            (schema as com.fasterxml.jackson.databind.node.ObjectNode).put("type", "object")
            mapOf("type" to "function", "function" to mapOf("name" to tool.name, "description" to tool.description, "parameters" to schema))
        }

    fun parse(node: JsonNode): List<FunctionCall> {
        val emptyArray = node.isArray && node.isEmpty
        if (node.isMissingNode || node.isNull || emptyArray) return emptyList()
        require(node.isArray && node.size() in 1..MAX_CALLS) { "Invalid native tool-call batch" }
        val calls =
            node.map { item ->
                val id =
                    item.path("id").asText("").ifBlank {
                        "call_" +
                            java.util.UUID
                                .randomUUID()
                                .toString()
                    }
                val name = item.path("function").path("name").asText("")
                val argumentNode = item.path("function").path("arguments")
                require(argumentNode.isMissingNode || argumentNode.isNull || argumentNode.isTextual) { "Native tool arguments must be a JSON-encoded string" }
                val arguments =
                    item
                        .path("function")
                        .path("arguments")
                        .asText("")
                        .ifBlank { "{}" }
                require(item.path("type").asText("function") == "function" && callId.matches(id) && functionName.matches(name)) { "Invalid native tool-call identity" }
                require(arguments.length <= MAX_ARGUMENT_CHARS) { "Native tool arguments exceed the decoding limit" }
                val args = NimProtocol.mapper.readTree(arguments)
                require(args != null && args.isObject) { "Native tool arguments must be a complete JSON object" }
                FunctionCall(id, name, NimProtocol.mapper.writeValueAsString(args))
            }
        require(calls.map { it.id }.distinct().size == calls.size) { "Duplicate native tool-call IDs" }
        return calls
    }

    fun envelope(
        call: FunctionCall,
        includeId: Boolean = false,
    ): String {
        val payload = mutableMapOf<String, Any>("tool" to call.name, "args" to NimProtocol.mapper.readTree(call.argumentsJson))
        if (includeId) payload["id"] = call.id
        return NimProtocol.mapper.writeValueAsString(payload)
    }

    fun wire(call: FunctionCall): Map<String, Any> =
        mapOf(
            "id" to call.id,
            "type" to "function",
            "function" to mapOf("name" to call.name, "arguments" to call.argumentsJson),
        )

    fun unsupported(response: TransportResponse): Boolean {
        if (response.statusCode !in setOf(NimHttpStatus.BAD_REQUEST, NimHttpStatus.UNPROCESSABLE)) return false
        val error = runCatching { NimProtocol.mapper.readTree(response.body).path("error") }.getOrNull()
        val text = (error?.path("message")?.asText("").orEmpty() + " " + error?.path("param")?.asText("").orEmpty()).lowercase()
        val concernsTools = listOf("tools", "tool_choice", "function calling", "tool calling").any { it in text }
        return concernsTools && listOf("unsupported", "not supported", "not allowed", "unknown parameter", "unrecognized").any { it in text }
    }
}
