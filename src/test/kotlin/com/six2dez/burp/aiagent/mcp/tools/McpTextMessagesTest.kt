package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.mock

class McpTextMessagesTest {
    @Test
    fun requestResponseAndTemplateBytesDoNotUseBurpsStringEncoding() {
        val text = "тест 🧪\nunchanged"
        val buffer = mock<ByteArray>()
        val service = mock<HttpService>()
        val request = mock<HttpRequest>()
        val response = mock<HttpResponse>()
        val captured = mutableListOf<kotlin.ByteArray>()
        mockStatic(ByteArray::class.java) { call ->
            captured.add(call.rawArguments.single() as kotlin.ByteArray)
            buffer
        }.use {
            mockStatic(HttpRequest::class.java).use { requests ->
                requests.`when`<HttpRequest> { HttpRequest.httpRequest(service, buffer) }.thenReturn(request)
                requests.`when`<HttpRequest> { HttpRequest.httpRequest(buffer) }.thenReturn(request)
                mockStatic(HttpResponse::class.java).use { responses ->
                    responses.`when`<HttpResponse> { HttpResponse.httpResponse(buffer) }.thenReturn(response)
                    assertEquals(request, McpTextMessages.request(service, text))
                    assertEquals(request, McpTextMessages.request(text))
                    assertEquals(response, McpTextMessages.response(text))
                    assertEquals(buffer, McpTextMessages.bytes(text))
                }
            }
        }
        assertEquals(4, captured.size)
        captured.forEach { assertArrayEquals(text.toByteArray(Charsets.UTF_8), it) }
    }
}
