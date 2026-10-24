package com.six2dez.burp.aiagent.ui

/** Presentation only: raw results remain in model history and the bounded execution journal. */
internal object ChatPresentation {
    const val LANGUAGE_INSTRUCTION =
        "Interactive conversation language: reply to the user in Russian by default, including conclusions and explanations. " +
            "Use another language only when the user explicitly requests it. Older profile/template instructions specifying English do not change this chat preference. " +
            "Keep tool identifiers, JSON schema keys, code, URLs and quoted evidence unchanged. Summarize relevant tool evidence; do not dump full tool outputs or internal followup instructions into the answer."

    fun visibleText(
        role: String,
        text: String,
    ): String? {
        val assistant = role.lowercase() in setOf("assistant", "ai")
        return when {
            role.startsWith("Tool result:") -> resultSummary(role.substringAfter(':').trim(), text)
            role.lowercase() in setOf("user", "you") && isInternalFollowup(text) -> null
            assistant && text.startsWith("Tool result (") && text.contains("):\n") ->
                resultSummary(text.substringAfter("Tool result (").substringBefore("):\n"), text.substringAfter("):\n"))
            assistant -> ToolCallParser.extractFirst(text)?.let { "Инструмент: ${toolName(it.tool)}. Данные скрыты; подробности — в Execution log." } ?: text
            else -> text
        }
    }

    fun resultSummary(
        tool: String,
        result: String,
    ): String {
        val status = if (result.startsWith("Error:") || result.contains("not authorised", ignoreCase = true)) "ошибка или отказ" else "ответ получен"
        return "Инструмент: ${toolName(tool)} — $status (${result.length} символов). Данные скрыты; подробности — в Execution log."
    }

    private fun isInternalFollowup(text: String): Boolean = (text.startsWith("Tool result for ") || text.startsWith("The tool call to ")) && text.contains("\nUser request:\n")

    private const val MAX_TOOL_NAME = 80

    private fun toolName(tool: String): String = tool.take(MAX_TOOL_NAME).replace(Regex("[^A-Za-z0-9_:.+-]"), "_")
}
