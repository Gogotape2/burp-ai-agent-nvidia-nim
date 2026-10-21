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
    val toolCallingMode: String = "auto",
    val inputTokenBudget: Int = 64_000,
    val compactContext: Boolean = true,
    val maxToolCalls: Int = DEFAULT_MAX_TOOL_CALLS,
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
            toolCallingMode = toolCallingMode.lowercase().takeIf { it in TOOL_CALLING_MODES } ?: "auto",
            inputTokenBudget = inputTokenBudget.coerceIn(MIN_INPUT_TOKENS, MAX_INPUT_TOKENS),
            maxToolCalls = maxToolCalls.coerceIn(1, MAX_TOOL_CALLS),
        )

    companion object {
        const val DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
        const val GLM_53_MODEL = "z-ai/glm-5.3"
        const val DEFAULT_TIMEOUT_SECONDS = 900
        const val DEFAULT_MAX_TOOL_CALLS = 24
        const val MAX_TOOL_CALLS = 128
        const val MIN_TIMEOUT_SECONDS = 30
        const val MAX_TIMEOUT_SECONDS = 3600
        const val MAX_COMPLETION_TOKENS = 32768
        const val MIN_INPUT_TOKENS = 4096
        const val MAX_INPUT_TOKENS = 1_000_000
        const val INPUT_TOKEN_STEP = 1024
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
        val TOOL_CALLING_MODES = listOf("auto", "native", "text")

        fun responseWaitMs(timeoutSeconds: Int): Long = TimeUnit.SECONDS.toMillis(timeoutSeconds.coerceIn(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS).toLong()) + COMPLETION_GRACE_MS
    }
}
