package com.six2dez.burp.aiagent.config

import java.util.concurrent.TimeUnit

data class NvidiaNimOptions(
    val maxTokens: Int = 16384,
    val reasoningEffort: String = "auto",
    val reasoningBudget: Int = 8192,
    val maxConcurrency: Int = 5,
    val rateLimit: Int = 30,
    val rateWindowSeconds: Int = 60,
    val maxRetries: Int = 2,
    val historyMaxChars: Int = 1_000_000,
) {
    fun validated(): NvidiaNimOptions =
        copy(
            maxTokens = maxTokens.coerceIn(1, MAX_COMPLETION_TOKENS),
            reasoningEffort = reasoningEffort.lowercase().takeIf { it in REASONING_MODES } ?: "auto",
            reasoningBudget = reasoningBudget.coerceIn(0, MAX_COMPLETION_TOKENS),
            maxConcurrency = maxConcurrency.coerceIn(1, MAX_CONCURRENCY),
            rateLimit = rateLimit.coerceIn(1, MAX_RATE_LIMIT),
            rateWindowSeconds = rateWindowSeconds.coerceIn(1, MAX_RATE_WINDOW_SECONDS),
            maxRetries = maxRetries.coerceIn(0, MAX_RETRIES),
            historyMaxChars = historyMaxChars.coerceIn(MIN_HISTORY_CHARS, MAX_HISTORY_CHARS),
        )

    companion object {
        const val DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
        const val DEFAULT_TIMEOUT_SECONDS = 900
        const val MIN_TIMEOUT_SECONDS = 30
        const val MAX_TIMEOUT_SECONDS = 3600
        const val MAX_COMPLETION_TOKENS = 32768
        const val MAX_CONCURRENCY = 32
        const val MAX_RATE_LIMIT = 6000
        const val MAX_RATE_WINDOW_SECONDS = 3600
        const val MAX_RETRIES = 5
        const val COMPLETION_GRACE_MS = 5000L
        const val TOKEN_SPINNER_STEP = 256
        const val HISTORY_SPINNER_STEP = 10_000
        const val MIN_HISTORY_CHARS = 40_000
        const val MAX_HISTORY_CHARS = 4_000_000
        const val MAX_HISTORY_MESSAGES = 200
        val REASONING_MODES = listOf("auto", "none", "low", "medium", "high", "max")

        fun responseWaitMs(timeoutSeconds: Int): Long = TimeUnit.SECONDS.toMillis(timeoutSeconds.coerceIn(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS).toLong()) + COMPLETION_GRACE_MS
    }
}
