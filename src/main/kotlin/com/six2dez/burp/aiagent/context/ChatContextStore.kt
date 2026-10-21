package com.six2dez.burp.aiagent.context

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.security.MessageDigest
import java.util.UUID

/** Session-local, bounded storage of already approved/redacted context; never persisted. */
class ChatContextStore {
    private val prefix = "ctx_" + UUID.randomUUID().toString().take(PREFIX_CHARS) + "_"
    private val entries = LinkedHashMap<String, String>(INITIAL_CAPACITY, LOAD_FACTOR, true)
    private val hashes = mutableMapOf<String, String>()
    private var totalChars = 0

    @Synchronized
    fun put(value: String): String {
        require(value.length <= MAX_CHARS) { "Context exceeds the local snapshot limit; request smaller pages" }
        val hash = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
        hashes[hash]?.takeIf { entries.containsKey(it) }?.let {
            entries[it]
            return it
        }
        while (entries.isNotEmpty() && (entries.size >= MAX_ENTRIES || totalChars + value.length > MAX_CHARS)) {
            val oldest = entries.entries.first()
            totalChars -= oldest.value.length
            entries.remove(oldest.key)
            hashes.values.removeAll { it == oldest.key }
        }
        val id = prefix + hash.take(HASH_CHARS)
        entries[id] = value
        hashes[hash] = id
        totalChars += value.length
        return id
    }

    @Synchronized
    fun read(
        id: String,
        offset: Int,
        count: Int,
        query: String? = null,
    ): String {
        require(offset >= 0 && count in 1..MAX_CHUNK_CHARS) { "offset must be nonnegative; count must be 1..$MAX_CHUNK_CHARS" }
        val value = entries[id] ?: error("Context reference is unavailable in this chat (expired, cleared, or from another chat). Retrieve the evidence again.")
        require(offset <= value.length) { "offset exceeds the snapshot length" }
        require(query == null || query.length in 1..MAX_QUERY_CHARS) { "query must contain 1..$MAX_QUERY_CHARS characters" }
        val match = query?.let { value.indexOf(it, offset, ignoreCase = true) }
        val start = match?.takeIf { it >= 0 } ?: offset
        val end = (start.toLong() + count).coerceAtMost(value.length.toLong()).toInt()
        val found = match == null || match >= 0
        return mapper.writeValueAsString(mapOf("id" to id, "offset" to start, "totalChars" to value.length, "text" to if (found) value.substring(start, end) else "", "found" to found, "nextOffset" to end.takeIf { found && it < value.length }))
    }

    @Synchronized
    fun size(): Int = entries.size

    @Synchronized
    fun clear() {
        entries.clear()
        hashes.clear()
        totalChars = 0
    }

    companion object {
        const val MAX_CHUNK_CHARS = 12_000
        const val MAX_CHARS = 2_000_000
        private const val MAX_ENTRIES = 48
        private const val MAX_QUERY_CHARS = 256
        private const val PREFIX_CHARS = 8
        private const val HASH_CHARS = 16
        private const val INITIAL_CAPACITY = 16
        private const val LOAD_FACTOR = 0.75f
        private val mapper = jacksonObjectMapper()
    }
}
