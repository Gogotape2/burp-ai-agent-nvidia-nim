package com.six2dez.burp.aiagent.backends.nvidia

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class NimConversationTest {
    private fun message(
        role: String,
        text: String,
    ) = mapOf("role" to role, "content" to text)

    @Test
    fun `failed user turn is merged with next user turn without losing either prompt`() {
        val prepared = NimConversation.prepare(listOf(message("system", "instructions"), message("user", "failed prompt")), "new prompt")
        assertEquals(listOf("system", "user"), prepared.messages.map { it["role"] })
        assertEquals("failed prompt\n\nnew prompt", prepared.messages.last()["content"])
        assertEquals(1, prepared.mergedTurns)
    }

    @Test
    fun `orphan assistant after history trim does not become the first conversation role`() {
        val prepared = NimConversation.prepare(listOf(message("system", "instructions"), message("assistant", "orphan"), message("user", "pending")), "current")
        assertEquals(listOf("system", "user"), prepared.messages.map { it["role"] })
        assertEquals(1, prepared.droppedOrphanAssistantTurns)
        assertEquals("pending\n\ncurrent", prepared.messages.last()["content"])
    }

    @Test
    fun `valid conversation is retained and adjacent tool summaries stay assistant messages`() {
        val input = listOf(message("system", "instructions"), message("user", "question"), message("assistant", "answer"), message("assistant", "tool summary"))
        val prepared = NimConversation.prepare(input, "next")
        assertEquals(listOf("system", "user", "assistant", "user"), prepared.messages.map { it["role"] })
        assertEquals("answer\n\ntool summary", prepared.messages[2]["content"])
        assertEquals("instructions", prepared.messages.first()["content"])
    }

    @Test
    fun `misplaced system or unknown tool role is rejected rather than promoted`() {
        assertThrows(IllegalArgumentException::class.java) {
            NimConversation.prepare(listOf(message("user", "question"), message("system", "untrusted instructions")), "next")
        }
        assertThrows(IllegalArgumentException::class.java) {
            NimConversation.prepare(listOf(message("tool", "unknown schema")), "next")
        }
    }
}
