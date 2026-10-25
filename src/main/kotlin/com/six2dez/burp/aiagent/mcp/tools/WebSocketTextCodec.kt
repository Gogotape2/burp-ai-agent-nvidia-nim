package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.util.utf8Prefix

/** Montoya's WebSocket String boundary is byte-oriented in Burp 2026.9.1, like its HTTP String factories. */
internal object WebSocketTextCodec {
    private const val UTF8_LOOKAHEAD_BYTES = 4
    private const val MAX_BYTE_CHAR = 255

    fun encode(text: String): String = String(text.toByteArray(Charsets.UTF_8), Charsets.ISO_8859_1)

    fun capture(raw: String): Pair<String, Int> {
        val bytesAsChars = raw.all { it.code <= MAX_BYTE_CHAR }
        val decoded =
            if (bytesAsChars) {
                String(raw.take(ActiveToolLimits.MAX_FRAME_BYTES + UTF8_LOOKAHEAD_BYTES).toByteArray(Charsets.ISO_8859_1), Charsets.UTF_8)
            } else {
                // Accommodate an implementation that already returns decoded wide characters.
                raw.take(ActiveToolLimits.MAX_FRAME_BYTES + UTF8_LOOKAHEAD_BYTES)
            }
        val originalBytes = if (bytesAsChars) raw.length else raw.toByteArray(Charsets.UTF_8).size
        return utf8Prefix(decoded, ActiveToolLimits.MAX_FRAME_BYTES) to originalBytes
    }
}
