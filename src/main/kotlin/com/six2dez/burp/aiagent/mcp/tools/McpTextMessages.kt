package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

/** Tool inputs are JSON text; use explicit UTF-8 rather than Burp's configurable string encoding. */
internal object McpTextMessages {
    // The Montoya byte overload is Java varargs, so a spread is required at this boundary.
    @Suppress("SpreadOperator")
    fun bytes(text: String): ByteArray = ByteArray.byteArray(*text.toByteArray(Charsets.UTF_8))

    // Binary payloads need the same bounded Java vararg boundary without any text encoding.
    @Suppress("SpreadOperator")
    fun binary(bytes: kotlin.ByteArray): ByteArray = ByteArray.byteArray(*bytes)

    fun request(
        service: HttpService,
        text: String,
    ): HttpRequest = HttpRequest.httpRequest(service, bytes(text))

    fun request(text: String): HttpRequest = HttpRequest.httpRequest(bytes(text))

    fun response(text: String): HttpResponse = HttpResponse.httpResponse(bytes(text))
}
