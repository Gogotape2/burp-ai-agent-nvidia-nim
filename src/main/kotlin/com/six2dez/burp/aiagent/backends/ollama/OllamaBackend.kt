package com.six2dez.burp.aiagent.backends.ollama

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
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
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

class OllamaBackend :
    AiBackend,
    HttpTransportAware {
    override val id: String = "ollama"
    override val displayName: String = "Ollama (local)"
    override val supportsSystemRole: Boolean = true

    private val mapper = ObjectMapper().registerKotlinModule()

    /**
     * Supervisor-injected [MontoyaHttpTransport] used by [healthCheck]; production wiring lives in
     * [com.six2dez.burp.aiagent.backends.BackendRegistry] (re-applied on every reload). Every request
     * of this backend, chat and health alike, goes through a Montoya transport and its egress gate.
     */
    @Volatile
    private var healthCheckTransport: MontoyaHttpTransport? = null

    override fun setHealthCheckTransport(transport: MontoyaHttpTransport) {
        healthCheckTransport = transport
    }

    override fun healthCheckTransport(): MontoyaHttpTransport? = healthCheckTransport

    companion object {
        private const val DEFAULT_CONTEXT_WINDOW = 8192

        // Bound for the one /api/show request that resolves the context window on the first send.
        private const val SHOW_TIMEOUT_MS = 5_000L

        private val NUM_CTX_PARAMETER = Regex("""num_ctx\s+(\d+)""")
    }

    /**
     * Phase 31 / D-08 / GATE-02: launching sends nothing. The context window is resolved by the
     * connection on its first send (see `OllamaConnection.contextWindowFor`), through the same bound
     * transport and egress gate as the chat request itself.
     */
    override fun launch(config: BackendLaunchConfig): AgentConnection {
        val baseUrl = config.baseUrl?.trimEnd('/') ?: "http://127.0.0.1:11434"
        val model = config.model?.ifBlank { "llama3.1" } ?: "llama3.1"
        val timeoutSeconds = (config.requestTimeoutSeconds ?: 120L).coerceIn(30L, 3600L)

        if (config.contextWindow != null && config.contextWindow != DEFAULT_CONTEXT_WINDOW) {
            BackendDiagnostics.log("[ollama] Using user-configured context window: ${config.contextWindow}")
        }

        return OllamaConnection(
            mapper = mapper,
            baseUrl = baseUrl,
            model = model,
            headers = config.headers,
            determinismMode = config.determinismMode,
            sessionId = config.sessionId,
            configuredContextWindow = config.contextWindow,
            circuitBreaker = HttpBackendSupport.newCircuitBreaker(),
            transport = config.transport,
            timeoutSeconds = timeoutSeconds,
            debugLog = { BackendDiagnostics.log("[ollama] $it") },
            errorLog = { BackendDiagnostics.logError("[ollama] $it") },
        )
    }

    override fun healthCheck(settings: AgentSettings): HealthCheckResult {
        val baseUrl = settings.ollamaUrl.trim()
        if (baseUrl.isBlank()) {
            return HealthCheckResult.Unavailable("Ollama URL is empty.")
        }
        val headers =
            HeaderParser.withBearerToken(
                settings.ollamaApiKey,
                HeaderParser.parse(settings.ollamaHeaders),
            )
        val url = "${baseUrl.trimEnd('/')}/api/tags"
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

    // ADR-17: twelve per-connection settings; a holder object would add an indirection on every send,
    // and re-baselining the finding is forbidden.
    @Suppress("LongParameterList")
    private class OllamaConnection(
        private val mapper: ObjectMapper,
        private val baseUrl: String,
        private val model: String,
        private val headers: Map<String, String>,
        private val determinismMode: Boolean,
        private val sessionId: String?,
        private val configuredContextWindow: Int?,
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
        // a blocked worker. Same worker name as before (`burp-ai-agent-ollama-connection`).
        private val exec = ExtensionThreads.scheduled("ollama-connection")
        private val runner =
            RetryingTurnRunner(exec, "ollama", "Ollama", circuitBreaker, ::isAlive, debugLog, errorLog)
        private val conversationHistory = ConversationHistory(20)
        private val lastTokenUsageRef = AtomicReference<TokenUsage?>(null)

        // D-08: a context window detected through /api/show, memoized for this connection. Only a
        // successful detection is stored; a failure or a refusal leaves it empty for the next send.
        private val detectedContextWindow = AtomicReference<Int?>(null)

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

            debugLog("send invoked (alive=${isAlive()}) textBytes=${text.toByteArray(Charsets.UTF_8).size}")
            runner.submit(
                prologue = {
                    lastTokenUsageRef.set(null)
                    debugLog("worker started on ${Thread.currentThread().name}")
                    if (history != null) {
                        conversationHistory.setHistory(history)
                    }
                    conversationHistory.setSystemPrompt(systemPrompt)
                },
                attempt = attempt@{ complete ->
                    // NET-01: Ollama MUST route through MontoyaHttpTransport so Burp's upstream
                    // proxy / SOCKS / cert store and the egress gate apply. A null transport
                    // means the supervisor's wiring is broken: fail fast, never send directly.
                    val boundTransport = checkNotNull(transport) { MontoyaHttpTransport.TRANSPORT_UNAVAILABLE }
                    // D-08 / GATE-02: resolved here, on the worker, before the first chat
                    // request; a refusal propagates as AiAccessRefusedException (never retried).
                    val numCtx = contextWindowFor(boundTransport)
                    debugLog("serialize start (model=$model, baseUrl=$baseUrl)")
                    // Add user message to conversation history
                    conversationHistory.addUser(text)
                    // Use non-streaming mode for better performance
                    val json =
                        buildChatJson(
                            model = model,
                            stream = false,
                            temperature = if (determinismMode) 0.0 else null,
                            numCtx = numCtx,
                            formatJson = jsonMode,
                            numPredict = maxOutputTokens,
                        )
                    debugLog("serialize done bytes=${json.toByteArray(Charsets.UTF_8).size}")

                    val endpointUrl = "$baseUrl/api/chat"
                    val allHeaders =
                        buildMap {
                            putAll(headers)
                            if (!sessionId.isNullOrBlank()) {
                                put("X-Session-Id", sessionId)
                            }
                        }

                    debugLog("request -> $endpointUrl (stream=false)")

                    val resp = boundTransport.post(endpointUrl, allHeaders, json, timeoutSeconds * 1000)
                    if (!resp.isSuccessful) {
                        errorLog("HTTP ${resp.statusCode}: ${resp.body.take(500)}")
                        circuitBreaker.recordHttpFailureIfRetryable(resp.statusCode)
                        // WR-04: bound the surfaced body (matches OpenAI/Anthropic .take(800))
                        // so a large/secret-laden error envelope isn't echoed wholesale into the
                        // chat bubble and persisted session.messages.
                        complete(IllegalStateException("Ollama HTTP ${resp.statusCode}: ${resp.body.take(800)}"))
                        return@attempt
                    }
                    debugLog("response <- HTTP ${resp.statusCode}")
                    val body = resp.body

                    if (body.isBlank()) {
                        complete(IllegalStateException("Ollama response body was empty"))
                        return@attempt
                    }
                    val node = mapper.readTree(body)
                    if (node.has("error")) {
                        val errText = node.path("error").asText()
                        errorLog("error: $errText")
                        complete(IllegalStateException("Ollama error: $errText"))
                        return@attempt
                    }

                    // Extract content from either 'content' or 'response' field. Use takeIf so
                    // a blank `message.content` (e.g. `{"message": {}}`) doesn't shadow a real
                    // value in the legacy `response` field.
                    val content =
                        node
                            .path("message")
                            .path("content")
                            .asText()
                            .takeIf { it.isNotBlank() }
                            ?: node.path("response").asText("")
                    val promptTokens = node.path("prompt_eval_count").asInt(-1)
                    val completionTokens = node.path("eval_count").asInt(-1)
                    if (promptTokens >= 0 || completionTokens >= 0) {
                        lastTokenUsageRef.set(
                            TokenUsage(
                                inputTokens = promptTokens.coerceAtLeast(0),
                                outputTokens = completionTokens.coerceAtLeast(0),
                            ),
                        )
                    }

                    if (content.isBlank()) {
                        // Snippet capped at 200 chars; the body can echo prompt content, so we
                        // keep this short — enough to diagnose response shape, not enough to
                        // leak meaningful prompt fragments into Burp's error log.
                        val snippet = body.take(200).replace("\n", " ")
                        errorLog("response content empty; raw body snippet: $snippet")
                        complete(
                            IllegalStateException(
                                "Ollama response content was empty. Raw body snippet: $snippet",
                            ),
                        )
                        return@attempt
                    }

                    debugLog("received complete response (${content.length} chars)")
                    // Add assistant response to conversation history
                    conversationHistory.addAssistant(content)
                    circuitBreaker.recordSuccess()
                    onChunk(content)
                    complete(null)
                },
                onComplete = onComplete,
            )
        }

        /**
         * D-08: the window sent as `num_ctx`. A configured value other than the 8192 default is used
         * as is; otherwise the window detected on an earlier send of this connection, else one
         * detection now (memoized on success), else the configured value.
         */
        private fun contextWindowFor(transport: MontoyaHttpTransport): Int? {
            val configured = configuredContextWindow
            if (configured != null && configured != DEFAULT_CONTEXT_WINDOW) return configured
            val detected = detectedContextWindow.get() ?: detectContextWindow(transport)?.also { detectedContextWindow.set(it) }
            return detected ?: configured
        }

        /**
         * Posts `/api/show` through the connection's transport and reads the model's context window:
         * `num_ctx` from the Modelfile `parameters` first, then `*.context_length` from `model_info`.
         * Returns null when nothing usable came back. A refusal is rethrown so the send fails with the
         * policy's text; any other failure is logged and answered with null (the caller's fallback).
         *
         * ADR-17: the broad catch is deliberate; detection is best effort, and a malformed or failed
         * answer must fall back to the configured window instead of failing the chat request.
         */
        @Suppress("TooGenericExceptionCaught")
        private fun detectContextWindow(transport: MontoyaHttpTransport): Int? {
            val fallback = configuredContextWindow
            return try {
                val requestJson = mapper.writeValueAsString(mapOf("name" to model))
                val resp = transport.post("$baseUrl/api/show", headers, requestJson, SHOW_TIMEOUT_MS)
                if (resp.isSuccessful) {
                    parseContextWindow(resp.body).also { detected ->
                        if (detected == null) {
                            debugLog("No context window found in /api/show response, using fallback: $fallback")
                        }
                    }
                } else {
                    debugLog("/api/show returned HTTP ${resp.statusCode}, using fallback: $fallback")
                    null
                }
            } catch (e: AiAccessRefusedException) {
                throw e
            } catch (e: Exception) {
                debugLog("Failed to detect context window: ${e.message}, using fallback: $fallback")
                null
            }
        }

        private fun parseContextWindow(body: String): Int? {
            if (body.isBlank()) return null
            val root = mapper.readTree(body)
            // Priority 1: explicit num_ctx in parameters (user Modelfile override)
            val fromParameters =
                NUM_CTX_PARAMETER
                    .find(root.path("parameters").asText(""))
                    ?.groupValues
                    ?.get(1)
                    ?.toIntOrNull()
                    ?.takeIf { it > 0 }
            // Priority 2: *.context_length in model_info (model default)
            val fromModelInfo =
                root
                    .path("model_info")
                    .takeIf { it.isObject }
                    ?.fields()
                    ?.asSequence()
                    ?.firstNotNullOfOrNull { (key, value) ->
                        value.asInt(-1).takeIf { key.endsWith(".context_length") && it > 0 }
                    }
            when {
                fromParameters != null -> debugLog("Detected context window from Modelfile parameters: $fromParameters")
                fromModelInfo != null -> debugLog("Detected context window from model_info: $fromModelInfo")
            }
            return fromParameters ?: fromModelInfo
        }

        private fun buildChatJson(
            model: String,
            stream: Boolean,
            temperature: Double?,
            numCtx: Int?,
            formatJson: Boolean = false,
            numPredict: Int? = null,
        ): String {
            val messages = conversationHistory.snapshot()
            val sb = StringBuilder(256)
            sb.append("{")
            sb.append("\"model\":\"").append(escapeJson(model)).append("\",")
            sb.append("\"messages\":[")
            messages.forEachIndexed { index, msg ->
                if (index > 0) sb.append(",")
                sb.append("{\"role\":\"").append(escapeJson(msg["role"] ?: "user"))
                sb.append("\",\"content\":\"").append(escapeJson(msg["content"] ?: ""))
                sb.append("\"}")
            }
            sb.append("],")
            sb.append("\"stream\":").append(if (stream) "true" else "false")
            if (formatJson) {
                sb.append(",\"format\":\"json\"")
            }
            if (temperature != null || numCtx != null || numPredict != null) {
                sb.append(",\"options\":{")
                var firstOpt = true
                if (temperature != null) {
                    sb.append("\"temperature\":").append(temperature)
                    firstOpt = false
                }
                if (numCtx != null) {
                    if (!firstOpt) sb.append(",")
                    sb.append("\"num_ctx\":").append(numCtx)
                    firstOpt = false
                }
                if (numPredict != null) {
                    if (!firstOpt) sb.append(",")
                    sb.append("\"num_predict\":").append(numPredict)
                }
                sb.append("}")
            }
            sb.append("}")
            return sb.toString()
        }

        private fun escapeJson(value: String): String {
            val out = StringBuilder(value.length + 16)
            value.forEach { ch ->
                when (ch) {
                    '\\' -> out.append("\\\\")
                    '"' -> out.append("\\\"")
                    '\n' -> out.append("\\n")
                    '\r' -> out.append("\\r")
                    '\t' -> out.append("\\t")
                    else -> {
                        if (ch < ' ') {
                            out.append(String.format(java.util.Locale.ROOT, "\\u%04x", ch.code))
                        } else {
                            out.append(ch)
                        }
                    }
                }
            }
            return out.toString()
        }

        override fun stop() {
            alive.set(false)
            // Cancels a pending retry and completes its turn before the worker goes away.
            runner.stop()
            exec.shutdownNow()
        }
    }
}
