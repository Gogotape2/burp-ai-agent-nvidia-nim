package com.six2dez.burp.aiagent.backends.nvidia

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.backends.TokenUsage
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import java.net.URI
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

internal object NimProtocol {
    val mapper: ObjectMapper = ObjectMapper().registerKotlinModule().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
    private const val MAX_RESPONSE_CHARS = 16 * 1024 * 1024
    private const val SSE_DATA_PREFIX_LENGTH = 5

    data class Completion(
        val content: String,
        val usage: TokenUsage?,
        val calls: List<com.six2dez.burp.aiagent.backends.FunctionCall> = emptyList(),
    )

    fun endpoint(baseUrl: String): String {
        val url = baseUrl.trim().trimEnd('/')
        val uri = URI(url)
        require(uri.scheme in listOf("http", "https") && !uri.host.isNullOrBlank()) { "NVIDIA NIM requires an HTTP(S) Base URL" }
        require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
            "NVIDIA NIM Base URL must not contain credentials, a query, or a fragment"
        }
        return when {
            url.endsWith("/chat/completions", true) -> url
            Regex(".*/v\\d+", RegexOption.IGNORE_CASE).matches(url) -> "$url/chat/completions"
            else -> "$url/v1/chat/completions"
        }
    }

    fun headers(input: Map<String, String>): Map<String, String> =
        input.filterKeys {
            it.lowercase() !in setOf("accept", "content-type", "content-length", "transfer-encoding", "connection", "host")
        } + mapOf("Accept" to "application/json")

    fun applyReasoning(
        payload: MutableMap<String, Any?>,
        model: String,
        options: NvidiaNimOptions,
        maxTokens: Int,
    ) {
        NimModelProfile.apply(payload, model, options, maxTokens)
    }

    fun parse(body: String): Completion {
        require(body.length <= MAX_RESPONSE_CHARS) { "NVIDIA NIM response exceeds the 16 MiB decoding limit" }
        val trimmed = body.trimStart('\uFEFF', ' ', '\r', '\n', '\t')
        require(trimmed.isNotBlank()) { "NVIDIA NIM returned an empty response" }
        // Some gateways buffer SSE despite stream=false. Accept only a complete, terminated stream.
        if (trimmed.startsWith("data:") || trimmed.startsWith(":") || trimmed.startsWith("event:")) return parseSse(trimmed)
        val node = mapper.readTree(trimmed)
        checkError(node)
        val choice = node.path("choices").path(0)
        val content = text(choice.path("message").path("content"))
        return completed(content, choice.path("finish_reason").asText(""), usage(node), NimNativeTools.parse(choice.path("message").path("tool_calls")))
    }

    private fun parseSse(body: String): Completion {
        val content = StringBuilder()
        val data = StringBuilder()
        var tokenUsage: TokenUsage? = null
        var finished = false
        var done = false
        var reason = ""
        val calls = NimSseToolCalls()

        fun flush() {
            if (data.isEmpty()) return
            val event = data.toString()
            data.setLength(0)
            if (event == "[DONE]") {
                done = true
                return
            }
            require(!done) { "NVIDIA NIM sent data after [DONE]" }
            val node = mapper.readTree(event)
            checkError(node)
            usage(node)?.let { tokenUsage = it }
            val choice = node.path("choices").path(0)
            content.append(text(choice.path("delta").path("content")))
            calls.append(choice.path("delta").path("tool_calls"))
            if (choice.path("finish_reason").isTextual) {
                finished = true
                reason = choice.path("finish_reason").asText()
            }
        }
        body.lineSequence().forEach { line ->
            when {
                line.isBlank() -> flush()
                line.startsWith("data:") -> {
                    if (data.isNotEmpty()) data.append('\n')
                    data.append(line.substring(SSE_DATA_PREFIX_LENGTH).removePrefix(" "))
                }
            }
        }
        flush()
        require(done || finished) { "NVIDIA NIM stream ended before a completion marker; response discarded" }
        val nativeCalls = if (reason in setOf("length", "content_filter")) emptyList() else calls.completed()
        return completed(content.toString(), reason, tokenUsage, nativeCalls)
    }

    private fun completed(
        content: String,
        reason: String,
        usage: TokenUsage?,
        calls: List<com.six2dez.burp.aiagent.backends.FunctionCall> = emptyList(),
    ): Completion {
        check(reason != "length") {
            "NVIDIA NIM reached max_tokens before finishing. Increase Max tokens or reduce Reasoning budget / effort."
        }
        check(reason != "content_filter") { "NVIDIA NIM filtered this response" }
        check(content.isNotBlank() || calls.isNotEmpty()) {
            "NVIDIA NIM returned no answer text (possibly reasoning-only). Increase Max tokens or reduce Reasoning effort."
        }
        return Completion(content, usage, calls)
    }

    private fun text(node: JsonNode): String =
        when {
            node.isTextual -> node.asText()
            node.isArray -> node.joinToString("") { it.path("text").asText("") }
            else -> ""
        }

    private fun checkError(node: JsonNode) {
        check(!node.hasNonNull("error")) { "NVIDIA NIM returned an API error in a successful HTTP response" }
    }

    private fun usage(node: JsonNode): TokenUsage? {
        val usage = node.path("usage")
        if (!usage.isObject) return null
        return TokenUsage(usage.path("prompt_tokens").asInt(0).coerceAtLeast(0), usage.path("completion_tokens").asInt(0).coerceAtLeast(0))
    }

    fun retryAfterMs(
        value: String?,
        nowMs: Long = System.currentTimeMillis(),
    ): Long? {
        if (value.isNullOrBlank()) return null
        val seconds = value.trim().toLongOrNull()
        return if (seconds != null) {
            TimeUnit.SECONDS.toMillis(seconds.coerceIn(0, NvidiaNimOptions.MAX_RATE_WINDOW_SECONDS.toLong()))
        } else {
            runCatching {
                (ZonedDateTime.parse(value.trim(), DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() - nowMs)
                    .coerceIn(0, NimRequestCoordinator.MAX_COOLDOWN_MS)
            }.getOrNull()
        }
    }
}
