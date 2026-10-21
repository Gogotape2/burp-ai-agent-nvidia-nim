package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.TransportResponse

/** Classify a refusal without exposing a provider's prompt/credential echo. */
internal object NimProviderRestriction {
    private const val MAX_BODY_CHARS = 8000

    fun describe(response: TransportResponse): String {
        val body = response.body.take(MAX_BODY_CHARS)
        val node = runCatching { NimProtocol.mapper.readTree(body) }.getOrNull()
        val reason =
            (
                node
                    ?.path("error")
                    ?.path("message")
                    ?.takeIf { it.isTextual }
                    ?.asText()
                    ?: node?.path("detail")?.takeIf { it.isTextual }?.asText()
                    ?: body.takeIf { !it.contains('<') && it.length < MAX_BODY_CHARS }.orEmpty()
            ).lowercase()
        val explanation =
            when {
                listOf("public api endpoints", "entitlement", "account verification", "model access").any { it in reason } ->
                    "The provider indicates an account/model access restriction. Check NVIDIA account verification and endpoint entitlement."
                listOf("terms of service", "terms of use", "content policy", "acceptable use", "policy violation", "content_filter").any { it in reason } ->
                    "The provider indicates a terms/content-policy restriction. Review the provider requirements or contact NVIDIA support."
                listOf("country", "region", "geographic", "jurisdiction").any { it in reason } ->
                    "The provider indicates a regional/legal access restriction. Check NVIDIA availability for the account and location."
                else -> "The provider or gateway refused this request with HTTP 451 (access/policy restriction); the exact reason was not identified."
            }
        return "$explanation No automatic retry for HTTP 451; increasing timeouts or token limits does not remove the restriction."
    }
}
