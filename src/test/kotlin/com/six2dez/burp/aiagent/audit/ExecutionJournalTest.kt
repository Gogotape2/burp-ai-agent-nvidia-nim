package com.six2dez.burp.aiagent.audit

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ExecutionJournalTest {
    @Test
    fun truncatedJsonCannotExposeASensitiveFieldThroughTheTextFallback() {
        val journal = ExecutionJournal()
        journal.add(ExecutionEntry(1, "trace", 1, "tool_result", "Large result", result = """{"password":"HIDDEN_TRUNCATED_SECRET","body":"${"data".repeat(6000)}"}"""))
        assertFalse(journal.exportPreview().contains("HIDDEN_TRUNCATED_SECRET"))
    }

    @Test
    fun exportPreviewRedactsNestedKeysHeadersProviderTokensAndUrlCredentials() {
        val key = "nvapi-" + "fixture".repeat(12)
        val journal = ExecutionJournal()
        val args =
            jacksonObjectMapper().writeValueAsString(
                mapOf(
                    "password" to "HIDDEN_PASSWORD",
                    "request" to "GET /?token=HIDDEN_QUERY HTTP/1.1\r\nAuthorization: Bearer HIDDEN_AUTH\r\nCookie: session=HIDDEN_COOKIE\r\n\r\n",
                    "nested" to mapOf("api_key" to key),
                    "note" to "visible evidence",
                ),
            )
        journal.add(ExecutionEntry(1, "trace-fixture", 2, "tool_requested", "Known tool", args, "Result includes $key"))
        val preview = journal.exportPreview()
        for (secret in listOf(key, "HIDDEN_PASSWORD", "HIDDEN_QUERY", "HIDDEN_AUTH", "HIDDEN_COOKIE")) assertFalse(preview.contains(secret), secret.take(6))
        assertTrue(preview.contains("visible evidence"))
        assertTrue(jacksonObjectMapper().readTree(preview).path("redacted").asBoolean())
    }

    @Test
    fun journalEvictsOldEntriesAndBoundsEachFieldBeforeExport() {
        val journal = ExecutionJournal()
        repeat(300) { journal.add(ExecutionEntry(it.toLong(), "trace", 1, "provider", "Event $it", result = "x".repeat(20_000))) }
        assertTrue(journal.snapshot().size <= 250)
        assertTrue(journal.snapshot().all { it.result!!.length <= 16_000 })
        assertTrue(jacksonObjectMapper().readTree(journal.exportPreview()).path("droppedEntries").asInt() > 0)
        journal.clear()
        assertTrue(journal.snapshot().isEmpty())
    }

    @Test
    fun deeplyNestedInputIsOmittedWithoutUnboundedTraversal() {
        val value = "[".repeat(50) + "\"private\"" + "]".repeat(50)
        assertTrue(DiagnosticSanitizer.sanitize(value).contains("OMITTED"))
    }
}
