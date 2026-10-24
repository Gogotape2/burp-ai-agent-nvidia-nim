package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.atomic.AtomicReference
import burp.api.montoya.core.ByteArray as MontoyaBytes

class MontoyaHttpRequestUtf8Test {
    @Test
    fun `JSON Cyrillic and emoji are passed as explicit UTF8 bytes without Burp string encoding`() {
        val body = """{"messages":[{"role":"user","content":"Привет 🚀 中文"}]}"""
        val captured = AtomicReference<ByteArray>()
        val request = mock<HttpRequest>(defaultAnswer = Mockito.RETURNS_SELF)
        val options = mock<RequestOptions>(defaultAnswer = Mockito.RETURNS_SELF)
        val bytes = mock<MontoyaBytes>()
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val url = "https://integrate.api.nvidia.com/v1/chat/completions"
        Mockito.mockStatic(HttpRequest::class.java).use { requests ->
            requests.`when`<HttpRequest> { HttpRequest.httpRequestFromUrl(url) }.thenReturn(request)
            Mockito.mockStatic(RequestOptions::class.java).use { requestOptions ->
                requestOptions.`when`<RequestOptions> { RequestOptions.requestOptions() }.thenReturn(options)
                Mockito
                    .mockStatic(MontoyaBytes::class.java) { call ->
                        captured.set(call.rawArguments[0] as ByteArray)
                        bytes
                    }.use {
                        whenever(api.http().sendRequest(any<HttpRequest>(), any<RequestOptions>()).response()).thenReturn(null)
                        MontoyaHttpTransport(api).post(url, emptyMap(), body)
                    }
            }
        }
        assertArrayEquals(body.toByteArray(Charsets.UTF_8), captured.get())
        verify(request).withBody(bytes)
        verify(request).withAddedHeader("Content-Type", "application/json; charset=utf-8")
        verify(request, never()).withBody(any<String>())
    }
}
