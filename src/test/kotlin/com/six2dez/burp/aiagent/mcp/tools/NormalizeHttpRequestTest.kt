package com.six2dez.burp.aiagent.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NormalizeHttpRequestTest {
    @Test
    fun updatesContentLengthForPostRequestWithLfOnlyLineEndings() {
        // Simulate a POST request with LF-only line endings (as MCP clients might send)
        // Original Content-Length is 4 (for "test")
        val input = "POST /api HTTP/1.1\nHost: example.com\nContent-Length: 4\n\ntest"

        val result = normalizeHttpRequest(input)

        // After normalization, line endings are CRLF
        assertTrue(result.contains("\r\n"), "Should have CRLF line endings")
        // Body is still "test" which is 4 bytes
        assertTrue(result.contains("Content-Length: 4"), "Content-Length should be 4 for 'test' body")
        assertTrue(result.endsWith("\r\n\r\ntest"), "Should have body after headers")
    }

    @Test
    fun preservesBodyNewlinesAndCalculatesTheirActualLength() {
        val body = "line1\nline2"
        val input = "POST /api HTTP/1.1\nHost: example.com\nContent-Length: 99\n\n$body"
        val result = normalizeHttpRequest(input)
        assertTrue(result.contains("Content-Length: 11"))
        assertEquals(body, result.substringAfter("\r\n\r\n"))
    }

    @Test
    fun preservesCorrectContentLengthForCrlfInput() {
        // Input already has CRLF line endings
        val input = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"

        val result = normalizeHttpRequest(input)

        assertEquals(input, result, "Should preserve correctly formatted request")
    }

    @Test
    fun handlesGetRequestWithoutBody() {
        val input = "GET /api HTTP/1.1\nHost: example.com\n\n"

        val result = normalizeHttpRequest(input)

        assertTrue(result.contains("\r\n"), "Should have CRLF line endings")
        assertTrue(result.endsWith("\r\n\r\n"), "Should end with empty body marker")
    }

    @Test
    fun handlesMixedLineEndings() {
        // Some \r\n, some \n, some \r
        val input = "POST /api HTTP/1.1\r\nHost: example.com\nContent-Length: 4\r\n\ntest"

        val result = normalizeHttpRequest(input)

        // All line endings should be normalized to CRLF
        val headerPart = result.substringBefore("\r\n\r\n")
        assertTrue(!headerPart.contains("\n\n"), "Should not have LF-only sequences")
        assertTrue(!headerPart.contains("\r\r"), "Should not have CR-only sequences")
    }

    @Test
    fun caseInsensitiveContentLengthHeader() {
        val input = "POST /api HTTP/1.1\nHost: example.com\ncontent-length: 4\n\ntest"

        val result = normalizeHttpRequest(input)

        // Should find and update the lowercase header
        assertTrue(
            result.contains("Content-Length: 4") ||
                result.contains("content-length: 4") ||
                result.lines().any { it.startsWith("Content-Length:", ignoreCase = true) && it.contains("4") },
            "Should update content-length header regardless of case",
        )
    }
}
