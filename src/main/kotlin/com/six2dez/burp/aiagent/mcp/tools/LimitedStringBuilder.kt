package com.six2dez.burp.aiagent.mcp.tools

/**
 * Byte-aware builder that stops appending once the configured UTF-8 limit is reached.
 * It is used by high-volume MCP tools to avoid building oversized intermediate strings.
 */
class LimitedStringBuilder(
    private val maxBytes: Int,
) {
    private val output = StringBuilder()
    private var byteCount = 0
    private var truncated = false

    init {
        require(maxBytes > 0) { "maxBytes must be > 0" }
    }

    /**
     * @return true when the full input is appended, false when truncation occurred.
     */
    fun append(value: String): Boolean {
        if (value.isEmpty()) return !truncated
        if (truncated) return false

        var index = 0
        while (index < value.length) {
            val point = value.codePointAt(index)
            val chars = String(Character.toChars(point))
            val chBytes = chars.toByteArray(Charsets.UTF_8).size
            if (byteCount + chBytes > maxBytes) {
                truncated = true
                return false
            }
            output.append(chars)
            byteCount += chBytes
            index += Character.charCount(point)
        }
        return true
    }

    fun build(): String {
        if (!truncated) return output.toString()

        val suffix = "... (truncated)"
        val suffixBytes = suffix.toByteArray(Charsets.UTF_8).size
        while (output.isNotEmpty() && byteCount + suffixBytes > maxBytes) {
            val last = output.codePointBefore(output.length)
            output.delete(output.length - Character.charCount(last), output.length)
            byteCount -= String(Character.toChars(last)).toByteArray(Charsets.UTF_8).size
        }
        if (byteCount + suffixBytes <= maxBytes) {
            output.append(suffix)
        }
        return output.toString()
    }
}
