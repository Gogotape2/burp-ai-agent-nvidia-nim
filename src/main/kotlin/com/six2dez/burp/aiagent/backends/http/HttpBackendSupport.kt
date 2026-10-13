package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.config.Defaults
import java.io.EOFException
import java.util.concurrent.ConcurrentLinkedDeque

object HttpBackendSupport {
    const val CIRCUIT_FAILURE_THRESHOLD: Int = 5
    const val CIRCUIT_RESET_TIMEOUT_MS: Long = 30_000
    const val CIRCUIT_HALF_OPEN_MAX_ATTEMPTS: Int = 1

    fun isRetryableConnectionError(e: Exception): Boolean {
        // Phase 31 / GATE-01 (Pitfall 3): a refusal is a policy outcome; a message that happens to say
        // "timeout" must never be retried six times or trip the circuit breaker.
        if (e is AiAccessRefusedException) return false
        if (e is EOFException) return true
        if (e is java.net.ConnectException || e is java.net.SocketTimeoutException) return true
        if (e is java.net.SocketException) return true
        val msg = e.message?.lowercase().orEmpty()
        return msg.contains("failed to connect") ||
            msg.contains("connection refused") ||
            msg.contains("timeout") ||
            msg.contains("unexpected end of stream") ||
            msg.contains("stream was reset") ||
            msg.contains("end of input")
    }

    fun retryDelayMs(attempt: Int): Long =
        when (attempt) {
            0 -> 500
            1 -> 1000
            2 -> 1500
            3 -> 2000
            4 -> 3000
            else -> 4000
        }

    /** Returns true for status codes that represent transient upstream overload or server errors.
     *  429 (rate-limited) and 5xx (server error) are retryable signals the circuit breaker should count.
     *  4xx config errors (400/401/403/404) are non-transient and must NOT trip the breaker. */
    fun isRetryableHttpStatus(statusCode: Int): Boolean = statusCode == 429 || statusCode in 500..599

    fun newCircuitBreaker(): CircuitBreaker =
        CircuitBreaker(
            failureThreshold = CIRCUIT_FAILURE_THRESHOLD,
            resetTimeoutMs = CIRCUIT_RESET_TIMEOUT_MS,
            halfOpenMaxAttempts = CIRCUIT_HALF_OPEN_MAX_ATTEMPTS,
        )

    fun openCircuitError(
        backendDisplayName: String,
        retryAfterMs: Long,
    ): IllegalStateException {
        val retryDelay = retryAfterMs.coerceAtLeast(1L)
        return IllegalStateException(
            "$backendDisplayName backend is temporarily unavailable (circuit open). Retry in ${retryDelay}ms.",
        )
    }
}

/** Records a circuit-breaker failure if [statusCode] is a retryable HTTP status (429 / 5xx).
 *  Call on every non-successful HTTP response BEFORE invoking onComplete, so the breaker sees
 *  upstream overload.  4xx config errors (400/401/403) pass through without recording —
 *  they are non-transient config errors that must NOT trip the breaker. */
fun CircuitBreaker.recordHttpFailureIfRetryable(statusCode: Int) {
    if (HttpBackendSupport.isRetryableHttpStatus(statusCode)) recordFailure()
}

class ConversationHistory(
    private val maxMessages: Int = Defaults.MAX_HISTORY_MESSAGES,
    private val maxTotalChars: Int = Defaults.MAX_HISTORY_TOTAL_CHARS,
) {
    private val history = ConcurrentLinkedDeque<Map<String, String>>()
    private val lock = Any()
    private var runningTotalChars: Int = 0

    @Volatile
    private var systemPromptEntry: Map<String, String>? = null

    fun addUser(content: String) {
        synchronized(lock) {
            val entry = mapOf("role" to "user", "content" to content)
            history.addLast(entry)
            runningTotalChars += entryChars(entry)
            trim()
        }
    }

    fun addAssistant(content: String) {
        synchronized(lock) {
            val entry = mapOf("role" to "assistant", "content" to content)
            history.addLast(entry)
            runningTotalChars += entryChars(entry)
            trim()
        }
    }

    fun setSystemPrompt(prompt: String?) {
        systemPromptEntry = if (prompt.isNullOrBlank()) null else mapOf("role" to "system", "content" to prompt)
    }

    fun snapshot(): List<Map<String, String>> {
        synchronized(lock) {
            val sys = systemPromptEntry
            val msgs = history.toList()
            return if (sys != null) listOf(sys) + msgs else msgs
        }
    }

    fun setHistory(newHistory: List<com.six2dez.burp.aiagent.backends.ChatMessage>) {
        synchronized(lock) {
            history.clear()
            runningTotalChars = 0
            newHistory.forEach { msg ->
                val entry = mapOf("role" to msg.role, "content" to msg.content)
                history.addLast(entry)
                runningTotalChars += entryChars(entry)
            }
            trim()
        }
    }

    private fun trim() {
        while (history.size > maxMessages) {
            val removed = history.pollFirst() ?: break
            runningTotalChars -= entryChars(removed)
        }
        while (history.size > MIN_MESSAGES_TO_KEEP && runningTotalChars > maxTotalChars) {
            val removed = history.pollFirst() ?: break
            runningTotalChars -= entryChars(removed)
        }
    }

    private fun entryChars(entry: Map<String, String>): Int = entry["role"].orEmpty().length + entry["content"].orEmpty().length + 2

    private companion object {
        private const val MIN_MESSAGES_TO_KEEP = 2
    }
}
