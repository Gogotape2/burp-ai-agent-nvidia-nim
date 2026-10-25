package com.six2dez.burp.aiagent.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class WebSocketTextCodecTest {
    @Test
    fun unicodeRoundTripMatchesRealUtf8WireBytes() {
        val text = "ASCII; ёж; 中文; 😀"
        val bridge = WebSocketTextCodec.encode(text)
        assertEquals(text, String(bridge.toByteArray(Charsets.ISO_8859_1), Charsets.UTF_8))
        val captured = WebSocketTextCodec.capture(bridge)
        assertEquals(text, captured.first)
        assertEquals(text.toByteArray().size, captured.second)
    }

    @Test
    fun capturesDoNotSplitMultibyteCharactersAtTheByteLimit() {
        val text = "a".repeat(ActiveToolLimits.MAX_FRAME_BYTES - 1) + "😀" + "z".repeat(20)
        val capture = WebSocketTextCodec.capture(WebSocketTextCodec.encode(text))
        assertEquals("a".repeat(ActiveToolLimits.MAX_FRAME_BYTES - 1), capture.first)
        assertFalse(capture.first.contains('\uFFFD'))
        assertEquals(text.toByteArray().size, capture.second)
    }
}
