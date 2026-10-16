package com.six2dez.burp.aiagent.backends.openai

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.HttpTransportAware
import com.six2dez.burp.aiagent.backends.JsonModeCapable
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.CircuitBreaker
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.RetryingTurnRunner
import com.six2dez.burp.aiagent.backends.http.recordHttpFailureIfRetryable
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.HeaderParser
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

// Every constructor parameter is a per-provider knob the NIM / Perplexity factories set; a holder
// class would trip constructorThreshold 10 as well. Answered in source (ADR-17 clause 1) because
// the quick-261008-kw4 health-provider signature change invalidated the old baseline entry.
@Suppress("LongParameterList")
class OpenAiCompatibleBackend(
    override val id: String = "openai-compatible",
    override val displayName: String = "Generic (OpenAI-compatible)",
    private val defaultBaseUrl: String = "",
    private val baseUrlSelector: (AgentSettings) -> String = { it.openAiCompatibleUrl.trim() },
    private val modelSelector: (AgentSettings) -> String = { it.openAiCompatibleModel.trim() },
    private val apiKeySelector: (AgentSettings) -> String = { it.openAiCompatibleApiKey },
    private val headersSelector: (AgentSettings) -> String = { it.openAiCompatibleHeaders },
    private val timeoutSelector: (AgentSettings) -> Int = { it.openAiCompatibleTimeoutSeconds },
    private val streaming: Boolean = false,
    private val defaultHeaders: Map<String, String> = emptyMap(),
    private val payloadCustomizer: ((MutableMap<String, Any?>) -> Unit)? = null,
    // Factory-specific health check. Receives the registry-injected transport explicitly so the
    // provider can never fall back to a direct socket (NIM / Perplexity return Unknown without it).
    private val healthCheckProvider: ((AgentSettings, MontoyaHttpTransport?) -> HealthCheckResult)? = null,
    // Path appended to a bare-host base URL (no /v\d+ and no /chat/completions). Defaults to the
    // OpenAI shape; Perplexity overrides to "/chat/completions" because its API has no /v1 prefix.
    private val chatCompletionsBasePath: String = "/v1/chat/completions",
    // OpenAI-style {"type":"json_object"} response_format. Perplexity's Sonar API rejects this
    // field, so set false there; the scanner prompts still ask the model for JSON in plain text.
    private val supportsJsonObjectResponseFormat: Boolean = true,
) : AiBackend,
    HttpTransportAware {
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    /**
     * [MontoyaHttpTransport] used by [healthCheck] and passed to factory-specific health-check
     * providers (NVIDIA NIM, Perplexity). [com.six2dez.burp.aiagent.backends.BackendRegistry] injects
     * it via [HttpTransportAware] and re-applies it after every reload, so the [AiBackend.healthCheck]
     * signature stays unchanged. Production and tests both go through a Montoya transport. With none
     * set (a test that never injected one), the generic check returns
     * Unavailable([MontoyaHttpTransport.TRANSPORT_UNAVAILABLE]) and the NIM / Perplexity providers
     * return Unknown, which the registry's egress gate answers before mapping it.
     */
    @Volatile
    private var healthCheckTransport: MontoyaHttpTransport? = null

    override fun setHealthCheckTransport(transport: MontoyaHttpTransport) {
        healthCheckTransport = transport
    }

    override fun healthCheckTransport(): MontoyaHttpTransport? = healthCheckTransport

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = effectiveBaseUrl(config.baseUrl)
        val model = config.model?.ifBlank { "" } ?: ""
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        val mergedHeaders = mergeHeaders(defaultHeaders, config.headers)
        return OpenAiCompatibleConnection(
            mapper = mapper,
            backendId = id,
            backendDisplayName = displayName,
            baseUrl = baseUrl,
            model = model,
            headers = mergedHeaders,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            streaming = streaming,
            payloadCustomizer = payloadCustomizer,
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            chatCompletionsBasePath = chatCompletionsBasePath,
            supportsJsonObjectResponseFormat = supportsJsonObjectResponseFormat,
            debugLog = { BackendDiagnostics.log("[$id] $it") },
            errorLog = { BackendDiagnostics.logError("[$id] $it") },
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        if (healthCheckProvider != null) {
            return healthCheckProvider.invoke(settings, healthCheckTransport)
        }
        val baseUrl = effectiveBaseUrl(baseUrlSelector(settings))
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("$displayName URL is empty.")
        }
        val headers =
            HeaderParser.withBearerToken(
                apiKeySelector(settings),
                HeaderParser.parse(headersSelector(settings)),
            )
        val modelsUrl = buildModelsUrl(baseUrl)
        val timeoutSeconds = timeoutSelector(settings).coerceIn(1, 30).toLong()
        // BUG-69-01 / NET-01: the supervisor-injected MontoyaHttpTransport makes the health check
        // honor Burp's upstream proxy / SOCKS / cert store and the egress gate. Without one the wiring
        // is broken: report Unavailable (never Unknown, which the registry could map to Healthy) and
        // send nothing.
        val transport = healthCheckTransport
        return if (transport != null) {
            transport.healthCheckGet(modelsUrl, headers, timeoutMs = timeoutSeconds * 1000)
        } else {
            HealthCheckResult.Unavailable(MontoyaHttpTransport.TRANSPORT_UNAVAILABLE)
        }
    }

    private class OpenAiCompatibleConnection(
        private val mapper: ObjectMapper,
        private val backendId: String,
        private val backendDisplayName: String,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val streaming: Boolean,
        private val payloadCustomizer: ((MutableMap<String, Any?>) -> Unit)?,
        private val transport: MontoyaHttpTransport?,
        private val timeoutSeconds: Long,
        private val chatCompletionsBasePath: String,
        private val supportsJsonObjectResponseFormat: Boolean,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit,
    ) : AgentConnection,
        UsageAwareConnection,
        JsonModeCapable {
        private val alive = AtomicBoolean(true)

        // Phase 34 / D-06: a scheduler, so a retry backoff is a one-shot task on this worker instead of
        // a blocked worker. Same worker name as before (`burp-ai-agent-<backendId>-connection`).
        private val exec = ExtensionThreads.scheduled("$backendId-connection")
        private val runner =
            RetryingTurnRunner(exec, backendId, backendDisplayName, circuitBreaker, ::isAlive, debugLog, errorLog)

        private val conversationHistory = ConversationHistory(20)
        private val lastTokenUsageRef = AtomicReference<TokenUsage?>(null)

        override fun isAlive(): Boolean = alive.get()

        override fun lastTokenUsage(): TokenUsage? = lastTokenUsageRef.get()

        override fun send(
            text: String,
            history: List<com.six2dez.burp.aiagent.backends.ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) {
            if (!isAlive()) {
                onComplete(IllegalStateException("Connection closed"))
                return
            }

            runner.submit(
                prologue = {
                    lastTokenUsageRef.set(null)
                    if (history != null) {
                        conversationHistory.setHistory(history)
                    }
                    conversationHistory.setSystemPrompt(systemPrompt)
                },
                attempt = attempt@{ complete ->
                    // BUG-69-01 / NET-01: AI HTTP backends go through MontoyaHttpTransport in
                    // production and in tests, so Burp's upstream proxy / SOCKS / cert store
                    // and the egress gate participate. Reaching this branch with transport ==
                    // null means the supervisor's wiring is broken: fail fast, never send directly.
                    if (transport == null) {
                        throw IllegalStateException(MontoyaHttpTransport.TRANSPORT_UNAVAILABLE)
                    }
                    conversationHistory.addUser(text)
                    val messages = conversationHistory.snapshot()
                    val payload =
                        mutableMapOf<String, Any?>(
                            "model" to model,
                            "messages" to messages,
                            "stream" to streaming,
                            "temperature" to if (determinismMode) 0.0 else 0.7,
                        )
                    payloadCustomizer?.invoke(payload)
                    if (maxOutputTokens != null) {
                        payload["max_tokens"] = maxOutputTokens
                    }
                    if (jsonMode && supportsJsonObjectResponseFormat) {
                        payload["response_format"] = mapOf("type" to "json_object")
                    }

                    val json = mapper.writeValueAsString(payload)
                    val endpointUrl = buildChatCompletionsUrl(baseUrl)

                    val allHeaders =
                        buildMap {
                            putAll(headers)
                            if (!sessionId.isNullOrBlank()) {
                                put("X-Session-Id", sessionId)
                            }
                        }

                    // Bug #66: pre-flight log shows the body SHAPE only — never the JSON itself
                    // and never the message content. This preserves the privacy guarantee
                    // (STRIDE T-quick-03) while giving operators enough to debug a 4xx.
                    val safeBodyPreview =
                        buildString {
                            append("model=").append(model)
                            append(" messages=").append(messages.size)
                            append(" json_bytes=").append(json.length)
                            if (jsonMode) append(" json_mode=true")
                            if (maxOutputTokens != null) append(" max_tokens=").append(maxOutputTokens)
                        }
                    debugLog("request -> POST $endpointUrl ($safeBodyPreview)")

                    val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                    if (!resp.isSuccessful) {
                        errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                        val message =
                            when (resp.statusCode) {
                                429 -> "$backendDisplayName rate limited (HTTP 429). Check quota/capacity or retry later."
                                // Bug #66: diagnosable 4xx — include the endpoint URL, a bounded
                                // body excerpt (T-quick-04: accepted up to 800 chars), and the
                                // standard remediation hint pointing at the three common causes.
                                else ->
                                    buildString {
                                        append("$backendDisplayName HTTP ${resp.statusCode} from POST ").append(endpointUrl)
                                        append("\nResponse: ").append(resp.body.take(800))
                                        append(
                                            "\nHints: verify the URL ends in /v1 (or /chat/completions), " +
                                                "the model name matches the provider's catalog, " +
                                                "and the API key is valid for this endpoint.",
                                        )
                                    }
                            }
                        circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
                        complete(IllegalStateException(message))
                        return@attempt
                    }
                    val body = resp.body
                    if (body.isBlank()) {
                        complete(IllegalStateException("$backendDisplayName response body was empty"))
                        return@attempt
                    }
                    // Single JSON document or (defensively) an SSE body from a server that
                    // streams regardless of "stream":false; see OpenAiResponseParser.
                    val parsed = OpenAiResponseParser.parse(mapper, body)
                    val content = parsed.content
                    parsed.usage?.let { lastTokenUsageRef.set(it) }
                    if (content.isBlank()) {
                        complete(IllegalStateException("$backendDisplayName response content was empty"))
                        return@attempt
                    }
                    debugLog("response <- ${content.take(200)}")
                    conversationHistory.addAssistant(content)
                    circuitBreaker.recordSuccess()
                    onChunk(content)
                    complete(null)
                },
                onComplete = onComplete,
            )
        }

        override fun stop() {
            alive.set(false)
            // Cancels a pending retry and completes its turn before the worker goes away.
            runner.stop()
            exec.shutdownNow()
        }

        private fun buildChatCompletionsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/chat/completions")) return trimmed
            if (versionedEndpointRegex.matches(trimmed)) return trimmed
            if (versionedBaseRegex.matches(trimmed)) return "$trimmed/chat/completions"
            // Bare host: append the backend-specific fallback path. Defaults to "/v1/chat/completions"
            // but Perplexity overrides to "/chat/completions" because its API exposes no /v1 prefix.
            val path = if (chatCompletionsBasePath.startsWith("/")) chatCompletionsBasePath else "/$chatCompletionsBasePath"
            return "$trimmed$path"
        }
    }

    private companion object {
        private val versionedBaseRegex = Regex(".*/v\\d+$", RegexOption.IGNORE_CASE)
        private val versionedEndpointRegex = Regex(".*/v\\d+/chat/completions$", RegexOption.IGNORE_CASE)

        private fun buildModelsUrl(baseUrl: String): String {
            val trimmed = baseUrl.trimEnd('/')
            val lower = trimmed.lowercase()
            if (lower.endsWith("/models")) return trimmed
            if (lower.endsWith("/chat/completions")) {
                return trimmed.substringBeforeLast("/chat/completions") + "/models"
            }
            if (versionedBaseRegex.matches(trimmed)) return "$trimmed/models"
            return "$trimmed/v1/models"
        }

        private fun mergeHeaders(
            defaults: Map<String, String>,
            overrides: Map<String, String>,
        ): Map<String, String> {
            if (defaults.isEmpty()) return overrides
            // Case-insensitive: a user-supplied "accept" replaces the default "Accept" instead of
            // travelling next to it (HTTP header names are case-insensitive).
            val merged = LinkedHashMap<String, String>()
            defaults.forEach { (name, value) ->
                if (overrides.keys.none { it.equals(name, ignoreCase = true) }) {
                    merged[name] = value
                }
            }
            merged.putAll(overrides)
            return merged
        }
    }

    private fun effectiveBaseUrl(candidate: String?): String {
        val trimmed = candidate?.trim()?.trimEnd('/').orEmpty()
        if (trimmed.isNotBlank()) {
            return trimmed
        }
        return defaultBaseUrl.trim().trimEnd('/')
    }
}
