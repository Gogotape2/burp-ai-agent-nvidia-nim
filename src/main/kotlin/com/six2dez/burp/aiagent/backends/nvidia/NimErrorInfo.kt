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

    fun acceptedBody(
        result: TransportResponse?,
        allowToolFallback: Boolean,
    ): String? {
        check(result?.statusCode != NimHttpStatus.ASYNC) {
            "NVIDIA NIM returned async HTTP 202. This backend requires synchronous chat completions; use a synchronous NIM endpoint."
        }
        if (result != null && allowToolFallback && NimNativeTools.unsupported(result)) throw NativeToolsUnsupported()
        return result?.takeIf { it.isSuccessful }?.body
    }

    fun httpError(
        response: TransportResponse,
        attempts: Int,
        shape: String,
        attemptStatuses: List<String> = emptyList(),
    ): Exception {
        val hint =
            when (response.statusCode) {
                NimHttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS -> NimProviderRestriction.describe(response)
                0 -> "Burp received no HTTP response. Check network/proxy settings and the total timeout."
                NimHttpStatus.UNAUTHORIZED, NimHttpStatus.FORBIDDEN -> "Check your NVIDIA API key and model access."
                NimHttpStatus.NOT_FOUND -> "Check Base URL and the complete vendor/model identifier, including nvidia/."
                NimHttpStatus.BAD_REQUEST, NimHttpStatus.UNPROCESSABLE -> "Check model parameters; for a different model, leave Reasoning effort on Auto."
                NimHttpStatus.RATE_LIMITED -> "NVIDIA rejected this attempt due to rate, quota or capacity limits. Wait before retrying; this can occur even with one request. Lower request limits if several chats or scanners are active."
                else -> NimErrorInfo.description(response)
            }
        // Provider bodies can echo prompts or credentials. Keep logs and UI errors metadata-only.
        val requestId = NimErrorInfo.requestId(response)?.let { " provider_request_id=$it" }.orEmpty()
        val statuses = attemptStatuses.takeIf { it.isNotEmpty() }?.joinToString(",", prefix = " http_statuses=").orEmpty()
        return IllegalStateException("NVIDIA NIM HTTP ${response.statusCode} after $attempts attempt(s). $hint\n$shape$statuses$requestId")
    }

    class NativeToolsUnsupported : IllegalStateException()
}
