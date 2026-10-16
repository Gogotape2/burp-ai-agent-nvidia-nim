package com.six2dez.burp.aiagent.backends.lmstudio

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

class LmStudioBackend :
    AiBackend,
    HttpTransportAware {
    override val id: String = "lmstudio"
    override val displayName: String = "LM Studio (local)"
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    /**
     * Supervisor-injected [MontoyaHttpTransport] used by [healthCheck]; production wiring lives in
     * [com.six2dez.burp.aiagent.backends.BackendRegistry] (re-applied on every reload). Production and
     * tests both go through a Montoya transport; with none, [healthCheck] reports it and sends nothing.
     */
    @Volatile
    private var healthCheckTransport: MontoyaHttpTransport? = null

    override fun setHealthCheckTransport(transport: MontoyaHttpTransport) {
        healthCheckTransport = transport
    }

    override fun healthCheckTransport(): MontoyaHttpTransport? = healthCheckTransport

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:1234"
        val model = config.model?.ifBlank { "lmstudio" } ?: "lmstudio"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)
        return LmStudioConnection(
            mapper,
            baseUrl,
            model,
            config.headers,
            config.determinismMode,
            config.sessionId,
            HttpBackendSupport.newCircuitBreaker(),
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            debugLog = { BackendDiagnostics.log("[lmstudio] $it") },
            errorLog = { BackendDiagnostics.logError("[lmstudio] $it") },
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.lmStudioUrl.trim()
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("LM Studio URL is empty.")
        }
        val headers =
            HeaderParser.withBearerToken(
                settings.lmStudioApiKey,
                HeaderParser.parse(settings.lmStudioHeaders),
            )
        val url = "${baseUrl.trimEnd('/')}/v1/models"
        // BUG-69-01 / NET-01: the supervisor-injected MontoyaHttpTransport makes the health check honor
        // Burp's upstream proxy / SOCKS / cert store and the egress gate. Without one the wiring is
        // broken: report Unavailable (never Unknown, which the registry could map to Healthy) and send
        // nothing.
        val transport = healthCheckTransport
        return if (transport != null) {
            transport.healthCheckGet(url, headers, timeoutMs = 3_000)
        } else {
            HealthCheckResult.Unavailable(MontoyaHttpTransport.TRANSPORT_UNAVAILABLE)
        }
    }

    private class LmStudioConnection(
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val circuitBreaker: CircuitBreaker,
        private val transport: MontoyaHttpTransport?,
        private val timeoutSeconds: Long,
        private val debugLog: (String) -> Unit,
        private val errorLog: (String) -> Unit,
    ) : AgentConnection,
        UsageAwareConnection,
        JsonModeCapable {
        private val alive = AtomicBoolean(true)

        // Phase 34 / D-06: a scheduler, so a retry backoff is a one-shot task on this worker instead of
        // a blocked worker. Same worker name as before (`burp-ai-agent-lmstudio-connection`).
        private val exec = ExtensionThreads.scheduled("lmstudio-connection")
        private val runner =
            RetryingTurnRunner(exec, "lmstudio", "LM Studio", circuitBreaker, ::isAlive, debugLog, errorLog)
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
                    // BUG-69-01 / NET-01: LM Studio routes through MontoyaHttpTransport in
                    // production and in tests, so Burp's upstream proxy / SOCKS / cert store
                    // and the egress gate participate. Reaching this branch with transport ==
                    // null means the supervisor's wiring is broken: fail fast, never send directly.
                    if (transport == null) {
                        throw IllegalStateException(MontoyaHttpTransport.TRANSPORT_UNAVAILABLE)
                    }
                    // Add user message to conversation history
                    conversationHistory.addUser(text)
                    val messages = conversationHistory.snapshot()
                    val payload =
                        mutableMapOf<String, Any>(
                            "model" to model,
                            "messages" to messages,
                            "stream" to false,
                            "temperature" to if (determinismMode) 0.0 else 0.7,
                        )
                    if (maxOutputTokens != null) {
                        payload["max_tokens"] = maxOutputTokens
                    }
                    if (jsonMode) {
                        payload["response_format"] = mapOf("type" to "json_object")
                    }

                    val json = mapper.writeValueAsString(payload)
                    val endpointUrl = "$baseUrl/v1/chat/completions"

                    val allHeaders =
                        buildMap {
                            putAll(headers)
                            if (!sessionId.isNullOrBlank()) {
                                put("X-Session-Id", sessionId)
                            }
                        }

                    debugLog("request -> $endpointUrl")

                    val resp = transport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                    if (!resp.isSuccessful) {
                        errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                        circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
                        // WR-04: bound the surfaced body (matches OpenAI/Anthropic .take(800))
                        // so a large/secret-laden error envelope isn't echoed wholesale into the
                        // chat bubble and persisted session.messages.
                        complete(IllegalStateException("LM Studio HTTP ${resp.statusCode}: ${resp.body.take(800)}"))
                        return@attempt
                    }
                    val body: String = resp.body

                    if (body.isBlank()) {
                        complete(IllegalStateException("LM Studio response body was empty"))
                        return@attempt
                    }
                    val node = mapper.readTree(body)
                    val choices = node.path("choices")
                    if (!choices.isArray || choices.isEmpty) {
                        // Snippet capped at 200 chars; see Ollama backend for rationale.
                        val snippet = body.take(200).replace("\n", " ")
                        errorLog("missing or empty 'choices' array; raw body snippet: $snippet")
                        complete(
                            IllegalStateException(
                                "LM Studio response had no 'choices'. Raw body snippet: $snippet",
                            ),
                        )
                        return@attempt
                    }
                    val content =
                        choices
                            .path(0)
                            .path("message")
                            .path("content")
                            .asText()
                    val usageNode = node.path("usage")
                    val promptTokens = usageNode.path("prompt_tokens").asInt(-1)
                    val completionTokens = usageNode.path("completion_tokens").asInt(-1)
                    if (promptTokens >= 0 || completionTokens >= 0) {
                        lastTokenUsageRef.set(
                            TokenUsage(
                                inputTokens = promptTokens.coerceAtLeast(0),
                                outputTokens = completionTokens.coerceAtLeast(0),
                            ),
                        )
                    }
                    if (content.isBlank()) {
                        val snippet = body.take(200).replace("\n", " ")
                        errorLog("response content empty; raw body snippet: $snippet")
                        complete(
                            IllegalStateException(
                                "LM Studio response content was empty. Raw body snippet: $snippet",
                            ),
                        )
                        return@attempt
                    }
                    debugLog("response <- ${content.take(200)}")
                    // Add assistant response to conversation history
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
    }
}
