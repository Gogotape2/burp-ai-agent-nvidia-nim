package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.TransportResponse
import java.util.concurrent.ThreadLocalRandom

internal object NimRetryPolicy {
    private const val SERVER_BACKOFF_MS = 5000L
    private const val RATE_LIMIT_BACKOFF_MS = 30_000L
    private const val MAX_BACKOFF_MS = 120_000L
    private const val MAX_EXPONENT = 4
    private const val JITTER_MS = 250L

    fun delayMs(
        response: TransportResponse?,
        attempt: Int,
    ): Long {
        val header =
            response
                ?.headers
                ?.entries
                ?.firstOrNull { it.key.equals("Retry-After", true) }
                ?.value
        val supplied = NimProtocol.retryAfterMs(header)
        val base = if (response?.statusCode == NimHttpStatus.RATE_LIMITED) RATE_LIMIT_BACKOFF_MS else SERVER_BACKOFF_MS
        return supplied ?: ((base shl attempt.coerceIn(0, MAX_EXPONENT)) + ThreadLocalRandom.current().nextLong(JITTER_MS)).coerceAtMost(MAX_BACKOFF_MS)
    }
}
