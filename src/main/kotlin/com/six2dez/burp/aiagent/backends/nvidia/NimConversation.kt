package com.six2dez.burp.aiagent.backends.nvidia

internal object NimConversation {
    data class Prepared(
        val messages: List<Map<String, String>>,
        val mergedTurns: Int,
        val droppedOrphanAssistantTurns: Int,
    ) {
        val inputChars: Int get() = messages.sumOf { it["content"].orEmpty().length }
        val roles: String get() = messages.joinToString(",") { it["role"].orEmpty() }
    }

    fun prepare(
        history: List<Map<String, String>>,
        currentUser: String,
    ): Prepared {
        require(currentUser.isNotBlank()) { "NVIDIA NIM cannot send an empty user message" }
        val system = history.firstOrNull()?.takeIf { it["role"] == "system" }
        val turns = if (system == null) history else history.drop(1)
        val normalized = mutableListOf<Map<String, String>>()
        var merged = 0
        var dropped = 0
        for (message in turns + mapOf("role" to "user", "content" to currentUser)) {
            val role = message["role"]
            require(role == "user" || role == "assistant") {
                "NVIDIA NIM history contains an unsupported or misplaced role. Open a new chat."
            }
            val content = message["content"].orEmpty()
            if (content.isBlank()) continue
            if (normalized.isEmpty() && role == "assistant") {
                // The shared history bound can evict a user while retaining its assistant reply.
                dropped++
            } else if (normalized.lastOrNull()?.get("role") == role) {
                // Failed sends leave pending user turns in the UI; preserve their text in one turn.
                val previous = normalized.removeLast()
                normalized.add(mapOf("role" to role, "content" to previous["content"].orEmpty() + "\n\n" + content))
                merged++
            } else {
                normalized.add(mapOf("role" to role, "content" to content))
            }
        }
        val messages = if (system == null) normalized.toList() else listOf(system) + normalized
        return Prepared(messages, merged, dropped)
    }
}
