package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.TransportResponse

/** Classify bounded provider errors without copying their potentially sensitive text into logs. */
internal object NimErrorInfo {
    private const val MAX_ERROR_CHARS = 8000
    private val requestIdPattern = Regex("[A-Za-z0-9_.:-]{8,120}")

    fun description(response: TransportResponse): String {
        val text = response.body.take(MAX_ERROR_CHARS).lowercase()
        return when {
            invalidRoles(text) ->
                "The provider rejected the conversation roles. Start a new chat if imported history still fails."
            contextLimit(text) ->
                "The provider reports a context-length limit. Reduce the attached context or start a new chat."
            "out of memory" in text || "overload" in text || "capacity" in text ->
                "The provider reports insufficient capacity. Reduce concurrent requests and retry after a pause."
            invalidReasoning(text) ->
                "The provider rejected a reasoning parameter. Check the selected model and Reasoning effort."
            else -> "The provider or gateway returned a server error. Retry after a pause; increasing the client timeout alone does not fix this HTTP status."
        }
    }

    private fun invalidRoles(text: String): Boolean = ("alternat" in text || "role" in text) && ("user" in text || "assistant" in text)

    private fun contextLimit(text: String): Boolean = "context" in text && ("length" in text || "window" in text || "too long" in text)

    private fun invalidReasoning(text: String): Boolean = "reasoning" in text && ("unsupported" in text || "invalid" in text)

    fun requestId(response: TransportResponse): String? =
        response.headers.entries
            .firstOrNull { it.key.equals("NVCF-REQID", true) || it.key.equals("X-Request-ID", true) }
            ?.value
            ?.takeIf { requestIdPattern.matches(it) && !it.startsWith("nvapi-", true) }
}
