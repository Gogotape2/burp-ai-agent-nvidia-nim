package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.core.JsonProcessingException
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.JsonModeCapable
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.UsageAwareConnection
import com.six2dez.burp.aiagent.backends.http.ConversationHistory
import com.six2dez.burp.aiagent.backends.http.HttpBackendSupport
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import java.net.SocketTimeoutException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CancellationException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class NvidiaNimConnection(
    private val config: BackendLaunchConfig,
    private val coordinator: NimRequestCoordinator = NimRequestCoordinator.shared,
) : AgentConnection,
    UsageAwareConnection,
    JsonModeCapable {
    private val options = config.nvidiaNimOptions.validated()
    private val timeoutSeconds = (config.requestTimeoutSeconds ?: NvidiaNimOptions.DEFAULT_TIMEOUT_SECONDS.toLong()).coerceIn(NvidiaNimOptions.MIN_TIMEOUT_SECONDS.toLong(), NvidiaNimOptions.MAX_TIMEOUT_SECONDS.toLong())
    private val endpoint = NimProtocol.endpoint(config.baseUrl.orEmpty().ifBlank { NvidiaNimBackendFactory.DEFAULT_BASE_URL })
    private val model = config.model.orEmpty().trim()
    private val headers = NimProtocol.headers(config.headers)
    private val alive = AtomicBoolean(true)
    private val pending = AtomicReference<Pending?>(null)
    private val usage = AtomicReference<TokenUsage?>(null)
    private val history = ConversationHistory(NvidiaNimOptions.MAX_HISTORY_MESSAGES, options.historyMaxChars)
    private val executor =
        ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(1),
            { task -> Thread(task, "nvidia-nim-connection").apply { isDaemon = true } },
        )

    private inner class Pending(
        val onChunk: (String) -> Unit,
        val onComplete: (Throwable?) -> Unit,
    ) {
        private val done = AtomicBoolean()

        // Callback implementations are external to this transport; always deliver one completion.
        @Suppress("TooGenericExceptionCaught")
        fun finish(
            error: Throwable?,
            content: String? = null,
        ) {
            if (!done.compareAndSet(false, true)) return
            pending.compareAndSet(this, null)
            var completionError = error
            try {
                if (error == null && content != null) onChunk(content)
            } catch (e: Exception) {
                completionError = e
            } finally {
                onComplete(completionError)
            }
        }
    }

    override fun isAlive(): Boolean = alive.get()

    override fun lastTokenUsage(): TokenUsage? = usage.get()

    // Async boundary: all ordinary failures must complete the request rather than escape the worker.
    @Suppress("TooGenericExceptionCaught")
    override fun send(
        text: String,
        history: List<ChatMessage>?,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        systemPrompt: String?,
        jsonMode: Boolean,
        maxOutputTokens: Int?,
    ) {
        if (!alive.get()) {
            onComplete(CancellationException("NVIDIA NIM connection is closed"))
            return
        }
        val request = Pending(onChunk, onComplete)
        if (!pending.compareAndSet(null, request)) {
            onComplete(IllegalStateException("NVIDIA NIM session is busy. Wait for its current answer or open another chat."))
            return
        }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        try {
            executor.execute {
                try {
                    val completion = completeTurn(text, history, systemPrompt, jsonMode, maxOutputTokens, deadline)
                    request.finish(null, completion.content)
                } catch (_: JsonProcessingException) {
                    // Do not retain Jackson's body excerpt in the exception cause or logs.
                    request.finish(IllegalStateException("NVIDIA NIM returned malformed JSON / SSE; response discarded"))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    request.finish(CancellationException("NVIDIA NIM request cancelled"))
                } catch (e: Exception) {
                    val safeError =
                        if (e.message.orEmpty().contains("Streaming response received", true)) {
                            IllegalStateException("The endpoint ignored stream=false and returned live SSE. Use a NIM endpoint or gateway that supports JSON responses.")
                        } else {
                            e
                        }
                    request.finish(safeError)
                }
            }
        } catch (e: RejectedExecutionException) {
            request.finish(CancellationException("NVIDIA NIM connection stopped before the request started").apply { initCause(e) })
        }
    }

    private fun completeTurn(
        text: String,
        history: List<ChatMessage>?,
        systemPrompt: String?,
        jsonMode: Boolean,
        maxOutputTokens: Int?,
        deadline: Long,
    ): NimProtocol.Completion {
        usage.set(null)
        require(model.isNotBlank()) { "NVIDIA NIM model is empty; use the full vendor/model identifier" }
        if (history != null) this.history.setHistory(history)
        this.history.setSystemPrompt(systemPrompt)
        // Build one immutable request; retries must never duplicate the user turn.
        val prepared = NimConversation.prepare(this.history.snapshot(), text)
        val messages = prepared.messages
        val tokens = (maxOutputTokens ?: options.maxTokens).coerceIn(1, NvidiaNimOptions.MAX_COMPLETION_TOKENS)
        val payload =
            mutableMapOf<String, Any?>(
                "model" to model,
                "messages" to messages,
                "stream" to false,
                "temperature" to if (config.determinismMode) 0.0 else 1.0,
                "max_tokens" to tokens,
            )
        NimProtocol.applyReasoning(payload, model, options, tokens)
        if (jsonMode) payload["response_format"] = mapOf("type" to "json_object")
        val json = NimProtocol.mapper.writeValueAsString(payload)
        val shape =
            "messages=${messages.size} roles=${prepared.roles} input_chars=${prepared.inputChars} max_tokens=$tokens " +
                "reasoning=${payload["reasoning_effort"] ?: "provider-default"} json_mode=$jsonMode"
        BackendDiagnostics.log("[nvidia-nim] request shape: $shape merged_turns=${prepared.mergedTurns} orphan_assistants_dropped=${prepared.droppedOrphanAssistantTurns}")
        val body = execute(json, deadline, shape)
        val completion = NimProtocol.parse(body)
        checkActive(deadline)
        this.history.addUser(text)
        this.history.addAssistant(completion.content)
        usage.set(completion.usage)
        BackendDiagnostics.log("[nvidia-nim] response complete: chars=${completion.content.length}")
        return completion
    }

    private fun execute(
        json: String,
        deadline: Long,
        shape: String,
    ): String {
        val transport = checkNotNull(config.transport) { "NVIDIA NIM requires Burp's Montoya HTTP transport" }
        for (attempt in 0..options.maxRetries) {
            checkActive(deadline)
            BackendDiagnostics.log("[nvidia-nim] POST attempt=${attempt + 1} stream=false")
            val (result, failure) = postAttempt(transport, json, deadline)
            checkActive(deadline)
            if (result != null && result.isSuccessful && result.statusCode != NimHttpStatus.ASYNC) return result.body
            check(result?.statusCode != NimHttpStatus.ASYNC) {
                "NVIDIA NIM returned async HTTP 202. This backend requires synchronous chat completions; use a synchronous NIM endpoint."
            }
            val retryable = result == null || NimHttpStatus.retryable(result.statusCode)
            val delay = NimRetryPolicy.delayMs(result, attempt)
            if (result != null && NimHttpStatus.retryable(result.statusCode)) coordinator.deferFor(delay)
            if (!retryable || attempt == options.maxRetries) throw failure ?: httpError(checkNotNull(result), attempt + 1, shape)
            if (TimeUnit.MILLISECONDS.toNanos(delay) >= deadline - System.nanoTime()) {
                throw SocketTimeoutException("NVIDIA NIM retry would exceed the ${timeoutSeconds}s total deadline")
            }
            BackendDiagnostics.log("[nvidia-nim] retry=${attempt + 1} status=${result?.statusCode ?: "connection"} wait_ms=$delay")
            BackendDiagnostics.logRetry("nvidia-nim", attempt + 1, delay, "HTTP ${result?.statusCode ?: "connection"}")
            Thread.sleep(delay)
        }
        error("NVIDIA NIM retry loop exhausted")
    }

    // Montoya can surface provider and transport failures as different runtime exception types.
    @Suppress("TooGenericExceptionCaught")
    private fun postAttempt(
        transport: MontoyaHttpTransport,
        json: String,
        deadline: Long,
    ): Pair<TransportResponse?, Exception?> =
        try {
            NimHttpCall(coordinator).post(transport, endpoint, headers, json, options, deadline) { !alive.get() } to null
        } catch (e: InterruptedException) {
            throw e
        } catch (e: Exception) {
            if (!HttpBackendSupport.isRetryableConnectionError(e)) throw e
            null to e
        }

    private fun checkActive(deadline: Long) {
        if (!alive.get() || Thread.currentThread().isInterrupted) throw CancellationException("NVIDIA NIM request cancelled")
        if (System.nanoTime() >= deadline) throw SocketTimeoutException("NVIDIA NIM exceeded the ${timeoutSeconds}s total deadline")
    }

    private fun httpError(
        response: TransportResponse,
        attempts: Int,
        shape: String,
    ): Exception {
        val hint =
            when (response.statusCode) {
                0 -> "Burp received no HTTP response. Check network/proxy settings and the total timeout."
                NimHttpStatus.UNAUTHORIZED, NimHttpStatus.FORBIDDEN -> "Check your NVIDIA API key and model access."
                NimHttpStatus.NOT_FOUND -> "Check Base URL and the complete vendor/model identifier, including nvidia/."
                NimHttpStatus.BAD_REQUEST, NimHttpStatus.UNPROCESSABLE -> "Check model parameters; for a different model, leave Reasoning effort on Auto."
                NimHttpStatus.RATE_LIMITED -> "NVIDIA rejected this attempt due to rate, quota or capacity limits. Wait before retrying; this can occur even with one request. Lower request limits if several chats or scanners are active."
                else -> NimErrorInfo.description(response)
            }
        // Provider bodies can echo prompts or credentials. Keep logs and UI errors metadata-only.
        val requestId = NimErrorInfo.requestId(response)?.let { " provider_request_id=$it" }.orEmpty()
        return IllegalStateException("NVIDIA NIM HTTP ${response.statusCode} after $attempts attempt(s). $hint\n$shape$requestId")
    }

    override fun stop() {
        alive.set(false)
        executor.shutdownNow()
        pending.get()?.finish(CancellationException("NVIDIA NIM request cancelled"))
    }
}
