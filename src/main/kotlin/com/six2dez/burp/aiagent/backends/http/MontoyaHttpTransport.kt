package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.util.ExtensionThreads
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities
import burp.api.montoya.core.ByteArray as MontoyaByteArray

data class TransportResponse(
    val statusCode: Int,
    val body: String,
    val isSuccessful: Boolean,
)

/**
 * Phase 31 / GATE-01 — the single egress choke point for AI-provider HTTP traffic.
 *
 * [post], [get] and [healthCheckGet] reach Montoya only through the private `execute`, whose FIRST
 * statement is [requireEgress]: before a thread is chosen and before any Montoya call, the injected
 * [ProviderEgressGate] is asked, on every request, whether a request for [boundBackendId] may leave
 * Burp now. A refused request throws [AiAccessRefusedException] and is never sent or queued.
 *
 * Core, never a backend, chooses the bound id: the supervisor builds one unbound root and hands each
 * backend [forBackend] views (the launch configuration and the registry's health-check injection).
 * An unbound transport refuses every request ([UNBOUND_REFUSAL]), so a wiring mistake fails closed.
 */
class MontoyaHttpTransport private constructor(
    private val api: MontoyaApi,
    private val gate: ProviderEgressGate,
    val boundBackendId: String?,
) {
    /** The unbound root. Production builds exactly one, in the supervisor, with the policy gate. */
    constructor(api: MontoyaApi, gate: ProviderEgressGate) : this(api, gate, null)

    /**
     * Gate-less and fail closed: its gate refuses every request with [NO_GATE_REFUSAL], also after
     * [forBackend]. It exists only so test spies that stub [post] / [get] keep compiling; production
     * code never uses it, and it can never let a request through.
     */
    constructor(api: MontoyaApi) : this(api, NO_GATE, null)

    /** A view bound to [backendId] that shares this transport's Montoya API and gate. */
    fun forBackend(backendId: String): MontoyaHttpTransport = MontoyaHttpTransport(api, gate, backendId)

    /**
     * Throws [AiAccessRefusedException] unless the gate allows a request for [boundBackendId] now:
     * with [UNBOUND_REFUSAL] when this transport was never bound, otherwise with the gate's own text.
     * Reads the gate on every call (D-04); it makes no Montoya call of its own.
     */
    fun requireEgress() {
        val backendId = boundBackendId ?: throw AiAccessRefusedException(UNBOUND_REFUSAL)
        gate.refusal(backendId)?.let { throw AiAccessRefusedException(it) }
    }

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
                .withBody(utf8Body(jsonBody))
                .withAddedHeader("Content-Type", "application/json; charset=utf-8")
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
                resp.statusCode == HTTP_TOO_MANY_REQUESTS ->
                    HealthCheckResult.Degraded("Endpoint reachable but rate limited (HTTP 429).")
                else -> HealthCheckResult.Unavailable("HTTP ${resp.statusCode}.")
            }
        } catch (e: Exception) {
            HealthCheckResult.Unavailable(e.message ?: "Request failed")
        }

    private fun execute(
        request: HttpRequest,
        timeoutMs: Long,
    ): TransportResponse {
        // GATE-01: FIRST statement, above the thread choice, so a refused request starts no thread.
        requireEgress()
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
                // result; the request is already bounded by timeoutMs. The worker's name,
                // burp-ai-agent-http-offedt, is the detector Phase 33's EDT tests look for: such a
                // thread during an EDT-01 action means that action blocked the EDT on a request.
                val task = FutureTask { api.http().sendRequest(request, options) }
                ExtensionThreads.newThread("http-offedt", task).start()
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
        const val UNBOUND_REFUSAL = "AI request refused: the HTTP transport is not bound to a backend."
        const val NO_GATE_REFUSAL = "AI request refused: this HTTP transport has no access gate."

        /** Phase 31 / NET-01: the fail-fast message of every HTTP backend adapter that was given no transport. */
        const val TRANSPORT_UNAVAILABLE = "MontoyaHttpTransport unavailable; AI HTTP backends require Burp's HTTP stack."

        private val NO_GATE = ProviderEgressGate { NO_GATE_REFUSAL }

        // Extra grace over the request's own response timeout before the off-EDT worker join gives up.
        private const val EDT_OFFLOAD_GRACE_MS = 5_000L

        // A rate-limited provider is reachable; the health pill reports Degraded, not Offline.
        private const val HTTP_TOO_MANY_REQUESTS = 429

        /**
         * Encodes a JSON request body as explicit UTF-8 bytes for Burp.
         *
         * Burp's String-to-message-bytes conversion keeps only the low byte of each char instead of
         * encoding it as UTF-8. That corrupted every non-ASCII character sent to the HTTP backends
         * and could even turn characters such as U+2022 or U+0122 into a raw JSON `"` byte
         * (#84 #85 #86 #88). `String.toByteArray(UTF_8)` maps an unpaired surrogate (e.g. from a
         * `take(n)` that split a pair) to '?', which is intended.
         *
         * The SpreadOperator suppression is deliberate: Montoya's only byte[] entry point is the
         * Java vararg `byteArray(byte...)`, Kotlin can pass an existing array to it only with a
         * spread, and one array copy per request is negligible next to the network round trip.
         * Answered in source per ADR-17 clause 1 rather than baselined.
         */
        @Suppress("SpreadOperator")
        private fun utf8Body(json: String): MontoyaByteArray = MontoyaByteArray.byteArray(*json.toByteArray(Charsets.UTF_8))

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
            )
        }
    }
}
