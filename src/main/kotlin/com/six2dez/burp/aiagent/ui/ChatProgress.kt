package com.six2dez.burp.aiagent.ui

import java.util.concurrent.TimeUnit

/** One task clock survives provider retries, queued batch members and tool/model transitions. */
internal class ChatProgress(
    val startedAtNanos: Long = System.nanoTime(),
) {
    var phaseStartedAtNanos: Long = startedAtNanos
        private set
    private var phaseKey = ""
    private var finalAnswer = false

    fun phase(
        stage: String,
        detail: String = "",
        now: Long = System.nanoTime(),
    ): String? {
        if (stage == "final") finalAnswer = true
        if (stage == "prepared") finalAnswer = false
        val label = phaseLabel(stage, detail) ?: return null
        val key = "$stage:$label"
        if (phaseKey != key) {
            phaseKey = key
            phaseStartedAtNanos = now
        }
        return label
    }

    private fun phaseLabel(
        stage: String,
        detail: String,
    ): String? {
        val finalPrefix = if (finalAnswer) "Итоговый ответ · " else ""
        return when (stage) {
            "prepared" -> "Подготовка запроса"
            "queue" -> "Очередь запросов расширения · ${attempt.find(detail)?.value.orEmpty()}"
            "provider" -> "${finalPrefix}Запрос отправлен · ожидание ответа NVIDIA NIM"
            "http" -> "Обработка ответа провайдера · ${http.find(detail)?.value.orEmpty()}"
            "retry" -> "Повтор запроса · ${http.find(detail)?.value ?: "ошибка соединения"} · пауза ${delay.find(detail)?.groupValues?.get(1) ?: "?"} мс"
            "fallback" -> "Переключение протокола инструментов"
            "final_answer_retry" -> "Подготовка итогового ответа · повтор без инструментов"
            "tool" -> "Выполняется инструмент ${detail.take(MAX_TOOL_NAME)}"
            "final" -> "Подготовка итогового ответа"
            else -> null
        }
    }

    companion object {
        private const val MAX_TOOL_NAME = 80
        private const val SECONDS_PER_MINUTE = 60
        private val attempt = Regex("[0-9]+/[0-9]+")
        private val http = Regex("HTTP [0-9]{3}")
        private val delay = Regex("after ([0-9]+)ms")

        fun elapsedLabel(
            description: String,
            started: Long,
            phaseStarted: Long,
            now: Long,
        ): String = "$description · всего ${duration(now - started)} · этап ${duration(now - phaseStarted)}"

        private fun duration(nanos: Long): String {
            val seconds = TimeUnit.NANOSECONDS.toSeconds(nanos.coerceAtLeast(0))
            return "%d:%02d".format(seconds / SECONDS_PER_MINUTE, seconds % SECONDS_PER_MINUTE)
        }
    }
}
