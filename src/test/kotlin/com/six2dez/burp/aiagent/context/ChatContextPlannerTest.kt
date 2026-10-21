package com.six2dez.burp.aiagent.context

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.backends.ChatMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChatContextPlannerTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun largeAttachmentRetainsExactEvidenceBehindAChatLocalReference() {
        val store = ChatContextStore()
        val original = mapper.writeValueAsString(mapOf("items" to listOf(mapOf("name" to "Selected finding", "detail" to "capture ".repeat(4000) + "FINAL_EVIDENCE_MARKER"))))
        val summary = mapper.readTree(ChatContextPlanner.compact(original, store, "Analyze selected finding", "Attachment"))
        assertFalse(summary.toString().contains("FINAL_EVIDENCE_MARKER"))
        val id = summary.path("contextRef").asText()
        val offset = original.indexOf("FINAL_EVIDENCE_MARKER")
        val retrieved = mapper.readTree(store.read(id, offset, 100))
        assertEquals(original.substring(offset), retrieved.path("text").asText())
        assertEquals(offset, mapper.readTree(store.read(id, 0, 100, "final_evidence_marker")).path("offset").asInt())
        assertFalse(mapper.readTree(store.read(id, 0, 100, "not-in-the-capture")).path("found").asBoolean())
        assertTrue(summary.path("notice").asText().contains("Summary only"))
    }

    @Test
    fun prettyPrintedCaptureDoesNotInventAnExactItemOffset() {
        val store = ChatContextStore()
        val raw = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapOf("items" to listOf(mapOf("name" to "Formatted issue", "detail" to "body ".repeat(3000)))))
        val summary = mapper.readTree(ChatContextPlanner.compact(raw, store, "Formatted issue", "Capture"))
        assertTrue(
            summary
                .path("selectedItems")
                .path(0)
                .path("sourceOffset")
                .isNull,
        )
        val result = mapper.readTree(store.read(summary.path("contextRef").asText(), 0, 200, "Formatted issue"))
        assertTrue(result.path("found").asBoolean())
        assertTrue(result.path("text").asText().contains("Formatted issue"))
    }

    @Test
    fun deduplicationAndPagingDoNotMixChatSnapshots() {
        val first = ChatContextStore()
        val other = ChatContextStore()
        val text = "first chunk\n".repeat(2000)
        val id = first.put(text)
        assertEquals(id, first.put(text))
        assertEquals(1, first.size())
        assertThrows(IllegalStateException::class.java) { other.read(id, 0, 100) }
        val joined = StringBuilder()
        var offset = 0
        do {
            val node = mapper.readTree(first.read(id, offset, 12000))
            joined.append(node.path("text").asText())
            offset = node.path("nextOffset").asInt(-1)
        } while (offset >= 0)
        assertEquals(text, joined.toString())
        assertThrows(IllegalArgumentException::class.java) { first.read(id, -1, 10) }
        assertThrows(IllegalArgumentException::class.java) { first.read(id, 0, 12001) }
        first.clear()
        assertThrows(IllegalStateException::class.java) { first.read(id, 0, 10) }
    }

    @Test
    fun evictionIsExplicitAndOversizedSnapshotsAreRejected() {
        val store = ChatContextStore()
        val oldest = store.put("old evidence")
        repeat(48) { store.put("new evidence $it") }
        assertTrue(store.size() <= 48)
        assertThrows(IllegalStateException::class.java) { store.read(oldest, 0, 10) }
        assertThrows(IllegalArgumentException::class.java) { store.put("x".repeat(ChatContextStore.MAX_CHARS + 1)) }
    }

    @Test
    fun inputBudgetCountsSystemAndSchemasAndDropsCompleteOldTurns() {
        val history =
            listOf(ChatMessage("user", "{\"contextRef\":\"ctx_fixture\"}"), ChatMessage("assistant", "Root evidence received")) +
                (1..20).flatMap { listOf(ChatMessage("user", "question $it " + "x".repeat(1000)), ChatMessage("assistant", "answer $it " + "y".repeat(1000))) }
        val result = ChatContextPlanner.budget(history, "current question", 2000, 2000, 4096, 100_000)
        assertTrue(result.removedMessages > 0)
        assertTrue(result.estimatedInputTokens <= 4096)
        assertEquals(history.first(), result.history.first())
        assertTrue(result.history.any { it.content.startsWith("question 20 ") })
        assertEquals(0, result.removedMessages % 2)
        assertThrows(IllegalArgumentException::class.java) { ChatContextPlanner.budget(emptyList(), "current", 20_000, 20_000, 4096, 100_000) }
    }

    @Test
    fun summaryIsBoundedAndReportsDuplicatesAndOmittedItems() {
        val item = mapOf("name" to "Finding", "detail" to "d".repeat(2000), "request" to "r".repeat(5000), "response" to "s".repeat(5000))
        val raw = mapper.writeValueAsString(mapOf("items" to listOf(item, item) + (1..30).map { item + ("name" to "Finding $it") }))
        val compact = ChatContextPlanner.compact(raw, ChatContextStore(), "Finding 30", "capture")
        assertTrue(compact.length <= 12000)
        val node = mapper.readTree(compact)
        assertEquals(32, node.path("totalItems").asInt())
        assertEquals(31, node.path("uniqueItems").asInt())
    }
}
