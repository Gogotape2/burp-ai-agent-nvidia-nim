package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.config.NvidiaNimOptions

internal object NimRequestShape {
    private val modelId = Regex("[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,128}")

    fun describe(
        config: BackendLaunchConfig,
        request: AgentChatRequest,
        messages: List<Map<String, Any?>>,
        native: Boolean,
        jsonChars: Int,
    ): String {
        val options = config.nvidiaNimOptions.validated()
        val model =
            config.model
                .orEmpty()
                .trim()
                .takeIf { modelId.matches(it) && !it.contains("nvapi-", true) && !it.contains("github_pat_", true) } ?: "[custom]"
        val tokens = (request.maxOutputTokens ?: options.maxTokens).coerceIn(1, NvidiaNimOptions.MAX_COMPLETION_TOKENS)
        return "model=$model protocol=${if (native) "native" else "text"} tools=${request.tools.size} " +
            "messages=${messages.size} roles=${messages.joinToString(",") { it["role"].toString() }} " +
            "input_chars=${messages.sumOf { it["content"]?.toString()?.length ?: 0 }} request_chars=$jsonChars " +
            "max_tokens=$tokens reasoning=${options.reasoningEffort} json_mode=${request.jsonMode}"
    }
}
