package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.core.JsonProcessingException
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.JsonModeCapable
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.backends.ToolCallingConnection
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
    ToolCallingConnection,
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
    private val nativeSession = NimNativeSession()
    private val encoder = NimTurnEncoder(config)
    private var nativeUnsupported = false
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
    ) = sendAgentTurn(
        AgentChatRequest(config.sessionId.orEmpty(), "nvidia-nim", text, history = history, systemPrompt = systemPrompt, jsonMode = jsonMode, maxOutputTokens = maxOutputTokens),
        onChunk,
        onComplete,
        {},
    )

    @Suppress("TooGenericExceptionCaught")
    override fun sendAgentTurn(
        request: AgentChatRequest,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        onEvent: (AgentTurnEvent) -> Unit,
    ) {
        if (!alive.get()) {
            onComplete(CancellationException("NVIDIA NIM connection is closed"))
            return
        }
        val pendingRequest = Pending(onChunk, onComplete)
        if (!pending.compareAndSet(null, pendingRequest)) {
            onComplete(IllegalStateException("NVIDIA NIM session is busy. Wait for its current answer or open another chat."))
            return
        }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        try {
            executor.execute {
                try {
                    val completion = completeTurn(request, deadline) { event -> runCatching { onEvent(event) } }
                    pendingRequest.finish(null, completion.content)
                } catch (_: JsonProcessingException) {
                    // Do not retain Jackson's body excerpt in the exception cause or logs.
                    pendingRequest.finish(IllegalStateException("NVIDIA NIM returned malformed JSON / SSE; response discarded"))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    pendingRequest.finish(CancellationException("NVIDIA NIM request cancelled"))
                } catch (e: Exception) {
                    val safeError =
                        if (e.message.orEmpty().contains("Streaming response received", true)) {
                            IllegalStateException("The endpoint ignored stream=false and returned live SSE. Use a NIM endpoint or gateway that supports JSON responses.")
                        } else {
                            e
                        }
                    pendingRequest.finish(safeError)
                }
            }
        } catch (e: RejectedExecutionException) {
            pendingRequest.finish(CancellationException("NVIDIA NIM connection stopped before the request started").apply { initCause(e) })
        }
    }

    private fun completeTurn(
        request: AgentChatRequest,
        deadline: Long,
        event: (AgentTurnEvent) -> Unit,
    ): NimProtocol.Completion {
        usage.set(null)
        require(model.isNotBlank()) { "NVIDIA NIM model is empty; use the full vendor/model identifier" }
        val native =
            !request.jsonMode &&
                options.toolCallingMode != "text" &&
                !nativeUnsupported &&
                (request.tools.isNotEmpty() || request.previousToolResult != null)
        request.history?.let { history.setHistory(it) }
        history.setSystemPrompt(encoder.textContract(request, native))
        val prepared = NimConversation.prepare(history.snapshot(), request.text)
        event(AgentTurnEvent("protocol", if (native) "Native function calling" else "Text/JSON response protocol"))
        val nativeTurn = nativeSession.prepare(request.copy(systemPrompt = encoder.textContract(request, native)), prepared.messages, native)
        nativeTurn.queuedCall?.let { call ->
            usage.set(TokenUsage(0, 0))
            event(AgentTurnEvent("tool_call", "Queued function call; no provider inference", call, TokenUsage(0, 0)))
            return NimProtocol.Completion(NimNativeTools.envelope(call), null)
        }
        val messages = nativeTurn.messages
        val json = encoder.requestJson(request, messages, native, nativeSession.definitions)
        val shape = NimRequestShape.describe(config, request, messages, native, json.length)
        BackendDiagnostics.log("[nvidia-nim] request shape: $shape merged_turns=${prepared.mergedTurns} orphan_assistants_dropped=${prepared.droppedOrphanAssistantTurns}")
        val body =
            try {
                execute(json, deadline, shape, native && options.toolCallingMode == "auto", event)
            } catch (_: NimErrorInfo.NativeToolsUnsupported) {
                nativeUnsupported = true
                event(AgentTurnEvent("fallback", "Endpoint rejected native tools; using the text protocol for this connection"))
                null
            }
        return if (body == null) {
            completeTurn(request, deadline, event)
        } else {
            val completion = NimProtocol.parse(body)
            val final =
                if (request.tools.isEmpty() && completion.calls.isNotEmpty()) {
                    // Some endpoints ignore tool_choice=none. Repair once without exposing another call.
                    event(AgentTurnEvent("final_answer_retry", "Provider ignored disabled tools; requesting one final answer without function definitions"))
                    val finalMessages = NimFinalAnswer.messages(messages)
                    val finalJson = encoder.requestJson(request, finalMessages, false, emptyList())
                    val finalShape = NimRequestShape.describe(config, request, finalMessages, false, finalJson.length)
                    val answer = NimProtocol.parse(execute(finalJson, deadline, finalShape, false, event))
                    check(NimFinalAnswer.isAnswer(answer)) { "Provider still requested tools after the final-answer retry; no extra tools were executed. Collected results remain in the conversation." }
                    answer.copy(usage = NimFinalAnswer.combinedUsage(completion.usage, answer.usage))
                } else {
                    completion
                }
            finishTurn(request, final, native, deadline, event)
        }
    }

    private fun finishTurn(
        request: AgentChatRequest,
        completion: NimProtocol.Completion,
        native: Boolean,
        deadline: Long,
        event: (AgentTurnEvent) -> Unit,
    ): NimProtocol.Completion {
        checkActive(deadline)
        check(native || completion.calls.isEmpty()) { "Endpoint returned native tool calls while the text protocol was selected" }
        val decoded = NimTextTools.recover(completion, request, native, event)
        val content =
            if (decoded.calls.isNotEmpty()) {
                check(request.tools.isNotEmpty()) { "Provider returned tool calls while tools were disabled" }
                val call = checkNotNull(nativeSession.accept(decoded))
                event(AgentTurnEvent("tool_call", "Function call (${decoded.calls.size} in batch)", call))
                NimNativeTools.envelope(call)
            } else {
                decoded.content
            }
        history.addUser(request.text)
        history.addAssistant(content)
        usage.set(completion.usage)
        completion.usage?.let { event(AgentTurnEvent("usage", "Provider tokens: input ${it.inputTokens}, output ${it.outputTokens}", usage = it)) }
        BackendDiagnostics.log("[nvidia-nim] response complete: chars=${content.length}")
        return decoded.copy(content = content)
    }

    private fun execute(
        json: String,
        deadline: Long,
        shape: String,
        allowToolFallback: Boolean,
        event: (AgentTurnEvent) -> Unit,
    ): String {
        val transport = checkNotNull(config.transport) { "NVIDIA NIM requires Burp's Montoya HTTP transport" }
        val statuses = mutableListOf<String>()
        for (attempt in 0..options.maxRetries) {
            checkActive(deadline)
            BackendDiagnostics.log("[nvidia-nim] POST attempt=${attempt + 1} stream=false")
            event(AgentTurnEvent("queue", "Attempt ${attempt + 1}/${options.maxRetries + 1}: waiting for a NIM request slot"))
            val (result, failure) = postAttempt(transport, json, deadline, event)
            statuses.add(NimHttpStatus.attemptLabel(result))
            result?.let { event(AgentTurnEvent("http", "Provider returned HTTP ${it.statusCode}")) }
            checkActive(deadline)
            val accepted = NimErrorInfo.acceptedBody(result, allowToolFallback)
            if (accepted != null) return accepted
            val retryable = result == null || NimHttpStatus.retryable(result.statusCode)
            val delay = NimRetryPolicy.delayMs(result, attempt)
            if (result != null && NimHttpStatus.retryable(result.statusCode)) coordinator.deferFor(delay)
            if (!retryable || attempt == options.maxRetries) throw failure ?: NimErrorInfo.httpError(checkNotNull(result), attempt + 1, shape, statuses)
            if (TimeUnit.MILLISECONDS.toNanos(delay) >= deadline - System.nanoTime()) {
                throw SocketTimeoutException("NVIDIA NIM retry would exceed the ${timeoutSeconds}s total deadline")
            }
            BackendDiagnostics.log("[nvidia-nim] retry=${attempt + 1} status=${result?.statusCode ?: "connection"} wait_ms=$delay")
            BackendDiagnostics.logRetry("nvidia-nim", attempt + 1, delay, "HTTP ${result?.statusCode ?: "connection"}")
            event(AgentTurnEvent("retry", "HTTP ${result?.statusCode ?: "connection"}; retry ${attempt + 1} after ${delay}ms"))
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
        event: (AgentTurnEvent) -> Unit,
    ): Pair<TransportResponse?, Exception?> =
        try {
            NimHttpCall(coordinator).post(transport, endpoint, headers, json, options, deadline, onSending = {
                event(AgentTurnEvent("provider", "Request sent; waiting for the provider response"))
            }, cancelled = { !alive.get() }) to null
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

    override fun stop() {
        alive.set(false)
        executor.shutdownNow()
        pending.get()?.finish(CancellationException("NVIDIA NIM request cancelled"))
    }
}
