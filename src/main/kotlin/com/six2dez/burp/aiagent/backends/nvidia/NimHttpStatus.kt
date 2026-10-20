package com.six2dez.burp.aiagent.backends.nvidia

internal object NimHttpStatus {
    const val ASYNC = 202
    const val BAD_REQUEST = 400
    const val UNAUTHORIZED = 401
    const val FORBIDDEN = 403
    const val NOT_FOUND = 404
    const val REQUEST_TIMEOUT = 408
    const val UNPROCESSABLE = 422
    const val RATE_LIMITED = 429
    private const val SERVER_ERROR_MIN = 500
    private const val SERVER_ERROR_MAX = 599

    fun retryable(status: Int): Boolean = status in setOf(0, REQUEST_TIMEOUT, RATE_LIMITED) || status in SERVER_ERROR_MIN..SERVER_ERROR_MAX
}
