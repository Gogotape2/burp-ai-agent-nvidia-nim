package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

data class TransportResponse(
    val statusCode: Int,
    val body: String,
    val isSuccessful: Boolean,
    val headers: Map<String, String> = emptyMap(),
)

class MontoyaHttpTransport(
    private val api: MontoyaApi,
) {
    // Montoya exposes the byte-array overload as Java varargs; explicit bytes avoid Burp's text encoding.
    @Suppress("SpreadOperator")
    fun post(
        url: String,
        headers: Map<String, String>,
        jsonBody: String,
        timeoutMs: Long = 120_000,
    ): TransportResponse {
        var request =
            HttpRequest
                .httpRequestFromUrl(url)
                .withMethod("POST")
                .withBody(ByteArray.byteArray(*jsonBody.toByteArray(Charsets.UTF_8)))
                .withAddedHeader("Content-Type", "application/json")
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun get(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): TransportResponse {
        var request = HttpRequest.httpRequestFromUrl(url)
        headers.forEach { (name, value) ->
            request = request.withAddedHeader(name, value)
        }
        return execute(request, timeoutMs)
    }

    fun healthCheckGet(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Long = 3_000,
    ): HealthCheckResult =
        try {
            val resp = get(url, headers, timeoutMs)
            when {
                resp.isSuccessful -> HealthCheckResult.Healthy
                resp.statusCode == 401 || resp.statusCode == 403 ->
                    HealthCheckResult.Degraded("Endpoint reachable but authentication failed (HTTP ${resp.statusCode}).")
                else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }

    private fun execute(
        request: HttpRequest,
        timeoutMs: Long,
    ): TransportResponse {
        val options =
            RequestOptions
                .requestOptions()
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutMs)
        val result =
            if (SwingUtilities.isEventDispatchThread()) {
                // Burp throws "Extensions should not make HTTP requests in the Swing event dispatch
                // thread" if sendRequest runs on the EDT (#80 — reached via the pre-send LM Studio /
                // Ollama health check). Run it on a short-lived daemon worker and block for the
                // result; the request is already bounded by timeoutMs.
                val task = FutureTask { api.http().sendRequest(request, options) }
                Thread(task, "montoya-http-offedt").apply { isDaemon = true }.start()
                try {
                    task.get(timeoutMs + EDT_OFFLOAD_GRACE_MS, TimeUnit.MILLISECONDS)
                } catch (e: ExecutionException) {
                    throw e.cause ?: e
                }
            } else {
                api.http().sendRequest(request, options)
            }
        return decodeResponse(result.response())
    }

    companion object {
        // Extra grace over the request's own response timeout before the off-EDT worker join gives up.
        private const val EDT_OFFLOAD_GRACE_MS = 5_000L

        // Force UTF-8: Montoya's bodyToString() decodes with the JVM platform charset, which mojibakes
        // multibyte responses (e.g. Chinese, emoji) on hosts whose default charset isn't UTF-8.
        // OpenAI-compatible servers commonly return Content-Type: application/json without an explicit
        // charset parameter, so we cannot rely on the server-declared charset either.
        internal fun decodeResponse(response: HttpResponse?): TransportResponse {
            val code = response?.statusCode()?.toInt() ?: 0
            val body = response?.body()?.bytes?.toString(Charsets.UTF_8) ?: ""
            return TransportResponse(
                statusCode = code,
                body = body,
                isSuccessful = code in 200..299,
                headers = response?.headers()?.associate { it.name() to it.value() }.orEmpty(),
            )
        }
    }
}
