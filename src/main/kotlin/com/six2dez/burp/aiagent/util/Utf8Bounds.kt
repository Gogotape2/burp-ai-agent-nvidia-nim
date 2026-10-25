package com.six2dez.burp.aiagent.util

private const val CONTINUATION_MASK = 0xC0
private const val CONTINUATION_BITS = 0x80

/** Never cut a UTF-8 code point in half, including supplementary Unicode characters. */
fun utf8Prefix(
    value: String,
    byteLimit: Int,
): String {
    val bytes = value.toByteArray(Charsets.UTF_8)
    if (bytes.size <= byteLimit.coerceAtLeast(0)) return value
    var end = byteLimit.coerceAtLeast(0)
    while (end > 0 && (bytes[end].toInt() and CONTINUATION_MASK) == CONTINUATION_BITS) end--
    return String(bytes, 0, end, Charsets.UTF_8)
}
