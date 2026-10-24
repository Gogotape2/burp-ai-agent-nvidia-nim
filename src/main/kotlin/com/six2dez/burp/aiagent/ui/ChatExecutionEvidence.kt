package com.six2dez.burp.aiagent.ui

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** UI status is derived from executed tools, never from the model's claim that it tested a target. */
internal class ChatExecutionEvidence(
    private val request: String,
) {
    private val attempted = mutableSetOf<String>()
    private val successful = mutableSetOf<String>()
    private var activeFailure = false
    private var denied = false

    fun recordDenied() {
        denied = true
    }

    fun record(
        tool: String,
        result: String?,
        failure: Boolean = false,
        argumentsJson: String? = null,
    ) {
        attempted.add(tool)
        val active = tool in ACTIVE_TOOLS && isActiveMode(tool, argumentsJson)
        val failed = failure || result == null || result.startsWith("Error:")
        if (active && failed) activeFailure = true
        if (active && !failed) successful.add(tool)
    }

    fun notice(): String? {
        if (!requestsPracticalCheck(request) || successful.any { it in ACTIVE_TOOLS }) return null
        return when {
            denied -> "Практическая проверка не выполнена: вызов инструмента не был разрешён. Правила подтверждения и область проверки сохраняются."
            activeFailure -> "Практическая проверка не завершена: инструмент вернул ошибку. Ответ модели не подтверждает выполнение проверки."
            attempted.isNotEmpty() -> "Практическая проверка не выполнена: вызовы инструментов не включали успешную отправку запроса или активную проверку."
            else -> "Практическая проверка не выполнена: модель ответила текстом, инструменты проверки не запускались."
        }
    }

    private fun isActiveMode(
        tool: String,
        arguments: String?,
    ): Boolean {
        if (tool == "http1_request" || tool == "http2_request") return true
        // Starting an empty audit or selecting passive checks does not send a verification request.
        return runCatching {
            val args = Json.parseToJsonElement(arguments.orEmpty()).jsonObject
            val hasRequests = args["requests"]?.jsonArray?.isNotEmpty() == true
            val active =
                if (tool == "scan_audit_start_mode") {
                    args["mode"]?.jsonPrimitive?.contentOrNull.equals("ACTIVE", ignoreCase = true)
                } else {
                    args["builtInConfiguration"]?.jsonPrimitive?.contentOrNull?.let { !it.contains("PASSIVE", ignoreCase = true) } == true
                }
            hasRequests && active
        }.getOrDefault(false)
    }

    companion object {
        val ACTIVE_TOOLS = setOf("http1_request", "http2_request", "scan_audit_start", "scan_audit_start_mode", "scan_audit_start_requests")
        private val explanatory = Regex("(?iuU)^\\s*(как\\b|объясни\\b|расскажи\\b|составь\\s+план|how\\b|explain\\b|describe\\b|plan\\b)")
        private val practical =
            Regex(
                "(?iuU)\\b(проверь|проверить|протестируй|подтверди|начни|запусти|выполни|приступи|verify|validate|test|check|run)\\b.{0,160}" +
                    "(на практике|практическ|реальн|уязвим|таргет|эндпоинт|активн|проверк|тестирован|target|vulnerab|endpoint|in practice|actually|active test)",
            )

        fun requestsPracticalCheck(text: String): Boolean = !explanatory.containsMatchIn(text) && practical.containsMatchIn(text)
    }
}
