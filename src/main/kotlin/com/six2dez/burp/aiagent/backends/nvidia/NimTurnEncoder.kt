package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.FunctionTool
import com.six2dez.burp.aiagent.config.NvidiaNimOptions

/** Encode one turn with a bounded payload and the selected function-call protocol. */
internal class NimTurnEncoder(
    private val config: BackendLaunchConfig,
) {
    private val options = config.nvidiaNimOptions.validated()
    private val model = config.model.orEmpty().trim()

    fun textContract(
        request: AgentChatRequest,
        native: Boolean,
    ): String? {
        val original = request.systemPrompt
        val needsSchemas = !native && request.tools.isNotEmpty() && original.orEmpty().contains("args_schema=").not()
        return if (needsSchemas) {
            original.orEmpty() + "\nUse standalone JSON {\"tool\":\"name\",\"args\":{}} to call a tool.\n" +
                request.tools.joinToString("\n") { "${it.name}: ${it.description} args_schema=${it.parametersJson}" }
        } else {
            original
        }
    }

    fun completionTokens(request: AgentChatRequest): Int = (request.maxOutputTokens ?: options.maxTokens).coerceIn(1, NvidiaNimOptions.MAX_COMPLETION_TOKENS)

    fun requestJson(
        request: AgentChatRequest,
        messages: List<Map<String, Any?>>,
        native: Boolean,
        definitions: List<FunctionTool>,
    ): String {
        val tokens = completionTokens(request)
        val payload =
            mutableMapOf<String, Any?>(
                "model" to model,
                "messages" to messages,
                "stream" to false,
                "temperature" to if (config.determinismMode) 0.0 else 1.0,
                "max_tokens" to tokens,
            )
        NimProtocol.applyReasoning(payload, model, options, tokens)
        if (native && definitions.isNotEmpty()) {
            payload["tools"] = NimNativeTools.definitions(definitions)
            payload["tool_choice"] = if (request.tools.isEmpty()) "none" else "auto"
        }
        if (request.jsonMode) payload["response_format"] = mapOf("type" to "json_object")
        val json = NimProtocol.mapper.writeValueAsString(payload)
        require(
            com.six2dez.burp.aiagent.context.ChatContextPlanner
                .estimateTokens(json.length.toLong()) <= options.inputTokenBudget,
        ) {
            "Serialized NIM request exceeds the estimated input budget. Reduce context or increase Input token budget."
        }
        return json
    }
}
