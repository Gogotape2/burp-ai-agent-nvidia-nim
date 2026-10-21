package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.FunctionCall
import com.six2dez.burp.aiagent.backends.FunctionResult
import com.six2dez.burp.aiagent.backends.FunctionTool

/** Drain one validated batch through the UI gate, in either provider protocol. */
internal class NimNativeSession {
    data class Prepared(
        val messages: List<Map<String, Any?>>,
        val queuedCall: FunctionCall?,
    )

    private var traceId: String? = null
    private var nativeProtocol = true
    private val messages = mutableListOf<Map<String, Any?>>()
    private val queued = ArrayDeque<FunctionCall>()
    private val seenIds = mutableSetOf<String>()
    private var active: FunctionCall? = null
    private var lastResult: FunctionResult? = null
    var definitions: List<FunctionTool> = emptyList()
        private set

    fun prepare(
        request: AgentChatRequest,
        initialMessages: List<Map<String, String>>,
        native: Boolean = true,
    ): Prepared {
        val result = request.previousToolResult
        if (result == null) {
            reset(request, initialMessages, native)
        } else {
            require(traceId == request.traceId) { "Tool result belongs to a different request" }
            val changed = nativeProtocol != native
            if (changed) switchToText(native)
            appendResult(result, changed)
            if (request.tools.isNotEmpty()) definitions = request.tools
        }
        if (request.tools.isEmpty()) {
            while (queued.isNotEmpty()) {
                appendResultMessage(FunctionResult(queued.removeFirst().id, "Not executed: tool execution stopped or its iteration budget was reached."))
            }
        }
        val next = queued.removeFirstOrNull()
        active = next
        if (messages.firstOrNull()?.get("role") == "system") messages.removeAt(0)
        request.systemPrompt?.takeIf { it.isNotBlank() }?.let { messages.add(0, mapOf("role" to "system", "content" to it)) }
        return Prepared(wireMessages(), next)
    }

    private fun reset(
        request: AgentChatRequest,
        initial: List<Map<String, String>>,
        native: Boolean,
    ) {
        definitions = request.tools
        traceId = request.traceId
        nativeProtocol = native
        messages.clear()
        messages.addAll(initial)
        queued.clear()
        seenIds.clear()
        active = null
        lastResult = null
    }

    private fun appendResult(
        result: FunctionResult,
        protocolChanged: Boolean,
    ) {
        if (active?.id == result.callId) {
            appendResultMessage(result)
            active = null
            lastResult = result
        } else {
            // A fallback restarts encoding after this result was already prepared for HTTP.
            require(protocolChanged && active == null && lastResult == result) { "Tool result does not match the active request" }
        }
    }

    private fun appendResultMessage(result: FunctionResult) {
        messages.add(
            if (nativeProtocol) {
                mapOf("role" to "tool", "tool_call_id" to result.callId, "content" to result.content)
            } else {
                mapOf("role" to "user", "content" to "Tool result for ${result.callId}:\n${result.content}")
            },
        )
    }

    private fun switchToText(native: Boolean) {
        require(!native) { "Cannot upgrade a running text tool chain to native functions" }
        val converted =
            messages.map { message ->
                when (message["role"]) {
                    "tool" -> mapOf("role" to "user", "content" to "Tool result for ${message["tool_call_id"]}:\n${message["content"]}")
                    "assistant" -> mapOf("role" to "assistant", "content" to if (message.containsKey("tool_calls")) "Assistant requested functions:\n${NimProtocol.mapper.writeValueAsString(message["tool_calls"])}" else message["content"])
                    else -> message
                }
            }
        messages.clear()
        messages.addAll(converted)
        nativeProtocol = false
    }

    private fun wireMessages(): List<Map<String, Any?>> {
        if (nativeProtocol) return messages.toList()
        val legacy = messages.map { mapOf("role" to it["role"].toString(), "content" to it["content"].toString()) }
        check(legacy.lastOrNull()?.get("role") == "user") { "Text tool exchange must end with a user/result turn" }
        return NimConversation.prepare(legacy.dropLast(1), legacy.last()["content"].orEmpty()).messages
    }

    fun accept(completion: NimProtocol.Completion): FunctionCall? {
        if (completion.calls.isEmpty()) return null
        require(completion.calls.none { it.id in seenIds }) { "Provider reused a tool-call ID" }
        seenIds.addAll(completion.calls.map { it.id })
        messages.add(
            if (nativeProtocol) {
                mapOf("role" to "assistant", "content" to completion.content.ifBlank { null }, "tool_calls" to completion.calls.map { NimNativeTools.wire(it) })
            } else {
                mapOf("role" to "assistant", "content" to completion.calls.joinToString("\n") { NimNativeTools.envelope(it, includeId = true) })
            },
        )
        queued.addAll(completion.calls)
        return queued.removeFirst().also { active = it }
    }
}
