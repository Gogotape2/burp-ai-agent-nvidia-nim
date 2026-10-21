package com.six2dez.burp.aiagent.context

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.backends.ChatMessage

internal object ChatContextPlanner {
    private val mapper = jacksonObjectMapper()
    private const val INLINE_CHARS = 12_000
    private const val EXCERPT_CHARS = 4_000
    private const val ITEM_EXCERPT_CHARS = 600
    private const val MIN_WORD_CHARS = 4
    private const val MAX_QUERY_WORDS = 32
    private const val ISSUE_PRIORITY = 10
    private const val MAX_SUMMARY_ITEMS = 8
    private const val CHARS_PER_TOKEN = 3
    private const val TOKEN_OVERHEAD = 32
    private const val MESSAGE_OVERHEAD = 16
    private const val MAX_HISTORY_MESSAGES = 200

    data class Budget(
        val history: List<ChatMessage>,
        val estimatedInputTokens: Int,
        val removedMessages: Int,
    )

    fun compact(
        raw: String,
        store: ChatContextStore,
        question: String,
        label: String,
    ): String {
        if (raw.length <= INLINE_CHARS) return raw
        return if (raw.length > ChatContextStore.MAX_CHARS) {
            "$label exceeds the local snapshot capacity (${raw.length} chars). Only the following excerpt is available; retrieve smaller pages from Burp.\n" + raw.take(EXCERPT_CHARS)
        } else {
            summarizeContext(raw, store, question, label)
        }
    }

    private fun summarizeContext(
        raw: String,
        store: ChatContextStore,
        question: String,
        label: String,
    ): String {
        val id = store.put(raw)
        val items = runCatching { mapper.readTree(raw).path("items").takeIf { it.isArray } }.getOrNull()
        val words =
            question
                .lowercase()
                .split(Regex("[^\\p{L}\\p{N}_]+"))
                .filter { it.length >= MIN_WORD_CHARS }
                .take(MAX_QUERY_WORDS)
        val unique = items?.distinctBy { it.toString() }.orEmpty()
        val ranked =
            unique.sortedByDescending { item ->
                val text = item.toString().lowercase()
                (if (item.has("name")) ISSUE_PRIORITY else 0) + words.count { it in text }
            }
        val summaries = ranked.take(MAX_SUMMARY_ITEMS).map { summarize(it, raw) }.toMutableList()
        val info =
            mapOf(
                "contextRef" to id,
                "label" to label,
                "totalChars" to raw.length,
                "retrieval" to "Use context_read with id=$id, offset and count<=12000 to inspect exact captured evidence before drawing conclusions.",
                "totalItems" to items?.size(),
                "uniqueItems" to unique.size,
                "selectedItems" to summaries,
                "excerpt" to if (items == null) raw.take(EXCERPT_CHARS) else null,
                "notice" to "Summary only. Capture-time body limits still apply. Full captured data remains in the snapshot until it expires.",
            )
        var json = mapper.writeValueAsString(info)
        while (json.length > INLINE_CHARS && summaries.isNotEmpty()) {
            summaries.removeLast()
            json = mapper.writeValueAsString(info)
        }
        return json
    }

    private fun summarize(
        item: JsonNode,
        raw: String,
    ): Map<String, Any?> =
        buildMap {
            for (key in listOf("name", "severity", "confidence", "affectedHost", "url", "method", "detail", "request", "response")) {
                item.get(key)?.takeUnless { it.isNull }?.let { put(key, it.asText().take(ITEM_EXCERPT_CHARS)) }
            }
            put("sourceOffset", raw.indexOf(item.toString()).takeIf { it >= 0 })
            put("itemChars", item.toString().length)
        }

    fun estimateTokens(chars: Long): Int = ((chars.coerceAtLeast(0) + CHARS_PER_TOKEN - 1) / CHARS_PER_TOKEN + TOKEN_OVERHEAD).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    fun budget(
        history: List<ChatMessage>,
        current: String,
        systemChars: Int,
        schemaChars: Int,
        inputTokens: Int,
        historyChars: Int,
    ): Budget {
        val groups = mutableListOf<MutableList<ChatMessage>>()
        for (message in history) {
            if (message.role == "user" || groups.isEmpty()) groups.add(mutableListOf())
            groups.last().add(message)
        }
        val base = current.length.toLong() + systemChars + schemaChars
        require(estimateTokens(base) <= inputTokens) { "Current prompt and tool schemas exceed the estimated input budget. Increase Input token budget or reduce the request/attachment." }

        fun retainedChars(): Long = groups.sumOf { group -> group.sumOf { it.content.length.toLong() + MESSAGE_OVERHEAD } }

        fun exceedsBudget(): Boolean {
            val tokenLimit = estimateTokens(base + retainedChars()) > inputTokens
            val charLimit = retainedChars() > historyChars
            val messageLimit = groups.sumOf { it.size } > MAX_HISTORY_MESSAGES
            return tokenLimit || charLimit || messageLimit
        }
        while (groups.isNotEmpty() && exceedsBudget()) {
            val pinFirst =
                groups
                    .first()
                    .firstOrNull()
                    ?.content
                    ?.contains("contextRef") == true
            groups.removeAt(if (pinFirst && groups.size > 1) 1 else 0)
        }
        val kept = groups.flatten()
        return Budget(kept, estimateTokens(base + retainedChars()), history.size - kept.size)
    }
}
