package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import com.six2dez.burp.aiagent.util.HeaderParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class NvidiaNimBackendFactory : AiBackendFactory {
    override fun create(): AiBackend {
        // Retain the supervisor's existing transport injection and backend registry contract.
        val backendRef = AtomicReference<OpenAiCompatibleBackend?>(null)
        val healthSnapshot = NimHealthSnapshot()
        val backend =
            OpenAiCompatibleBackend(
                id = "nvidia-nim",
                displayName = "NVIDIA NIM",
                defaultBaseUrl = DEFAULT_BASE_URL,
                baseUrlSelector = { it.nvidiaNimUrl.trim() },
                modelSelector = { it.nvidiaNimModel.trim() },
                apiKeySelector = { it.nvidiaNimApiKey },
                headersSelector = { it.nvidiaNimHeaders },
                timeoutSelector = { it.nvidiaNimTimeoutSeconds },
                healthCheckProvider = { settings ->
                    healthSnapshot.record(settings, nimHealthCheck(settings, backendRef.get()?.healthCheckTransport()))
                },
            ).apply {
                setBackgroundHealthCheckProvider(healthSnapshot::current)
                setConnectionFactory { NvidiaNimConnection(it) }
            }
        backendRef.set(backend)
        return backend
    }

    companion object {
        const val DEFAULT_BASE_URL: String = "https://integrate.api.nvidia.com"
        private const val HEALTH_TIMEOUT_SECONDS = 120
        private const val HEALTH_MAX_TOKENS = 16
        private const val REASONING_HEALTH_MAX_TOKENS = 1024

        private fun nimHealthCheck(
            settings: AgentSettings,
            transport: MontoyaHttpTransport?,
        ): HealthCheckResult {
            val model = settings.nvidiaNimModel.trim()
            if (model.isBlank()) return HealthCheckResult.Unavailable("NVIDIA NIM model is empty.")
            return try {
                val tokens = if (model.startsWith("nvidia/nemotron-3-ultra-", true)) HEALTH_MAX_TOKENS else REASONING_HEALTH_MAX_TOKENS
                val url = NimProtocol.endpoint(settings.nvidiaNimUrl.ifBlank { DEFAULT_BASE_URL })
                val headers = NimProtocol.headers(HeaderParser.withBearerToken(settings.nvidiaNimApiKey, HeaderParser.parse(settings.nvidiaNimHeaders)))
                val payload =
                    mutableMapOf<String, Any?>(
                        "model" to model,
                        "messages" to listOf(mapOf("role" to "user", "content" to "Reply OK.")),
                        "max_tokens" to tokens,
                        "temperature" to 0.0,
                        "stream" to false,
                    )
                NimProtocol.applyReasoning(payload, model, settings.nvidiaNimOptions.copy(reasoningEffort = "none"), tokens)
                val json = NimProtocol.mapper.writeValueAsString(payload)
                val timeoutSeconds = settings.nvidiaNimTimeoutSeconds.coerceIn(NvidiaNimOptions.MIN_TIMEOUT_SECONDS, HEALTH_TIMEOUT_SECONDS).toLong()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
                val gate = NimRequestCoordinator.shared
                val options = settings.nvidiaNimOptions.validated()
                val response =
                    if (transport != null) {
                        NimHttpCall(gate).post(transport, url, headers, json, options, deadline) { false }
                    } else {
                        // Test-only fallback; production always injects Burp's transport.
                        testOnlyPost(url, headers, json, timeoutSeconds)
                    }
                healthResult(response)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                HealthCheckResult.Unavailable("NVIDIA NIM connection test cancelled")
            } catch (e: Exception) {
                HealthCheckResult.Unavailable("NVIDIA NIM connection test failed (${e.javaClass.simpleName}). Check network / timeout / Base URL.")
            }
        }

        private fun testOnlyPost(
            url: String,
            headers: Map<String, String>,
            json: String,
            timeoutSeconds: Long,
        ): TransportResponse {
            val request =
                Request
                    .Builder()
                    .url(url)
                    .post(json.toRequestBody("application/json".toMediaType()))
                    .apply { headers.forEach { (name, value) -> header(name, value) } }
                    .build()
            return HttpBackendSupport.sharedClient(url, timeoutSeconds).newCall(request).execute().use {
                TransportResponse(it.code, "", it.isSuccessful)
            }
        }

        private fun healthResult(response: TransportResponse): HealthCheckResult =
            when {
                response.isSuccessful && response.statusCode != NimHttpStatus.ASYNC -> HealthCheckResult.Healthy
                response.statusCode in listOf(NimHttpStatus.UNAUTHORIZED, NimHttpStatus.FORBIDDEN) -> HealthCheckResult.Degraded("Authentication failed (HTTP ${response.statusCode}). Check API key / model access.")
                response.statusCode == NimHttpStatus.RATE_LIMITED -> HealthCheckResult.Degraded("Rate limited (HTTP 429). Reduce NIM request limits.")
                response.statusCode == NimHttpStatus.NOT_FOUND -> HealthCheckResult.Unavailable("HTTP 404. Check Base URL and full vendor/model identifier.")
                else -> HealthCheckResult.Unavailable("NVIDIA NIM HTTP ${response.statusCode}.")
            }
    }
}
