package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.TokenUsage

/** Preserve observed evidence while removing executable function metadata from a final-answer repair. */
internal object NimFinalAnswer {
    private const val INSTRUCTION =
        "Tool execution has ended. No additional function calls will run. " +
            "Give the final answer from the user request and the observed results below. " +
            "Distinguish verified facts from checks that remain incomplete. " +
            "Do not output function calls, tool JSON, or claim that any unexecuted check succeeded."

    fun messages(previous: List<Map<String, Any?>>): List<Map<String, Any?>> {
        val originalSystem =
            previous
                .firstOrNull { it["role"] == "system" }
                ?.get("content")
                ?.toString()
                .orEmpty()
        val system = mapOf("role" to "system", "content" to listOf(originalSystem, INSTRUCTION).filter { it.isNotBlank() }.joinToString("\n\n"))
        val evidence =
            previous.filter { it["role"] != "system" }.map { message ->
                val role = message["role"]?.toString()
                val content = message["content"]?.toString().orEmpty()
                when (role) {
                    "tool" -> mapOf("role" to "user", "content" to "Observed function result (${message["tool_call_id"]}):\n$content")
                    "assistant" -> mapOf("role" to role, "content" to if (message.containsKey("tool_calls")) "Previously handled function requests:\n${NimProtocol.mapper.writeValueAsString(message["tool_calls"])}\n$content" else content)
                    else -> {
                        require(role == "user") { "Unexpected role in final-answer evidence" }
                        mapOf("role" to role, "content" to content)
                    }
                }
            }
        return NimConversation.prepare(listOf(system) + evidence, INSTRUCTION).messages
    }

    fun isAnswer(completion: NimProtocol.Completion): Boolean = completion.calls.isEmpty() && runCatching { NimTextTools.parse(completion.content).isNullOrEmpty() }.getOrDefault(false)

    fun combinedUsage(
        first: TokenUsage?,
        second: TokenUsage?,
    ): TokenUsage? = if (first == null || second == null) null else TokenUsage(sum(first.inputTokens, second.inputTokens), sum(first.outputTokens, second.outputTokens))

    private fun sum(
        first: Int,
        second: Int,
    ): Int = (first.toLong() + second).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
}
