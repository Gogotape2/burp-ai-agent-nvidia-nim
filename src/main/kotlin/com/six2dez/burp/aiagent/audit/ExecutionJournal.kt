package com.six2dez.burp.aiagent.audit

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

data class ExecutionEntry(
    val timeMs: Long,
    val traceId: String,
    val step: Int,
    val stage: String,
    val detail: String,
    val arguments: String? = null,
    val result: String? = null,
)

/** Bounded, session-local diagnostics. Export is redacted independently of chat privacy mode. */
class ExecutionJournal {
    private val entries = ArrayDeque<ExecutionEntry>()
    private var chars = 0
    private var dropped = 0

    @Synchronized
    fun add(entry: ExecutionEntry) {
        val bounded = entry.copy(detail = entry.detail.take(FIELD_LIMIT), arguments = entry.arguments?.take(FIELD_LIMIT), result = entry.result?.take(FIELD_LIMIT))
        while (entries.isNotEmpty() && (entries.size >= ENTRY_LIMIT || chars + size(bounded) > TOTAL_LIMIT)) {
            chars -= size(entries.removeFirst())
            dropped++
        }
        entries.addLast(bounded)
        chars += size(bounded)
    }

    @Synchronized
    fun snapshot(): List<ExecutionEntry> = entries.toList()

    @Synchronized
    fun clear() {
        entries.clear()
        chars = 0
        dropped = 0
    }

    fun exportPreview(): String {
        val captured = synchronized(this) { entries.toList() to dropped }
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(
            mapOf(
                "format" to "burp-ai-agent-diagnostics-v1",
                "droppedEntries" to captured.second,
                "fieldLimitChars" to FIELD_LIMIT,
                "redacted" to true,
                "events" to
                    captured.first.map { entry ->
                        entry.copy(
                            detail = DiagnosticSanitizer.sanitize(entry.detail),
                            arguments = entry.arguments?.let { DiagnosticSanitizer.sanitize(it) },
                            result = entry.result?.let { DiagnosticSanitizer.sanitize(it) },
                        )
                    },
            ),
        )
    }

    private fun size(entry: ExecutionEntry): Int = entry.detail.length + (entry.arguments?.length ?: 0) + (entry.result?.length ?: 0)

    companion object {
        private const val FIELD_LIMIT = 16_000
        private const val ENTRY_LIMIT = 250
        private const val TOTAL_LIMIT = 1_000_000
        private val mapper = jacksonObjectMapper()
    }
}
