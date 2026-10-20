package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.config.NvidiaNimOptions

/** Only send knobs documented by the selected model's NIM endpoint. */
internal object NimModelProfile {
    fun apply(
        payload: MutableMap<String, Any?>,
        model: String,
        options: NvidiaNimOptions,
        maxTokens: Int,
    ) {
        when {
            model.startsWith("nvidia/nemotron-3-ultra-", true) -> {
                val effort = if (options.reasoningEffort == "auto") "none" else options.reasoningEffort
                require(effort in listOf("none", "medium", "high")) {
                    "Nemotron Ultra supports reasoning none / medium / high. Select Auto for a fast answer."
                }
                payload["reasoning_effort"] = effort
                if (effort == "high") payload["reasoning_budget"] = minOf(options.reasoningBudget, (maxTokens - 1).coerceAtLeast(0))
            }
            model.equals("z-ai/glm-5.3", true) || model.equals("z-ai/glm-5.3-flash", true) -> {
                val effort = if (options.reasoningEffort in listOf("auto", "none")) "low" else options.reasoningEffort
                require(effort in listOf("low", "high", "max")) {
                    "GLM 5.3 supports reasoning low / high / max. Select Auto for low; reasoning cannot be disabled."
                }
                payload["reasoning_effort"] = effort
                payload["chat_template_kwargs"] = mapOf("clear_thinking" to true)
            }
        }
    }
}
