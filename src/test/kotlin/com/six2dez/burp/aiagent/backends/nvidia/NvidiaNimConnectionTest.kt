package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class NvidiaNimConnectionTest {
    @Test
    fun `factory sends JSON with long timeout and preserves scanner output cap`() {
        val transport =
            transport { json, headers, timeout ->
                val body = NimProtocol.mapper.readTree(json)
                assertFalse(body.path("stream").asBoolean())
                assertEquals(512, body.path("max_tokens").asInt())
                assertEquals("none", body.path("reasoning_effort").asText())
                assertEquals("application/json", headers["Accept"])
                assertTrue(timeout in 890_000..900_000)
                ok()
            }
        val connection = NvidiaNimBackendFactory().create().launch(config(transport))
        try {
            assertNull(send(connection, maxTokens = 512))
        } finally {
            connection.stop()
        }
    }

    @Test
    fun `429 retries same immutable body and next turn has no duplicate user message`() {
        val requests = mutableListOf<String>()
        val transport =
            transport { json, _, _ ->
                requests.add(json)
                if (requests.size == 1) TransportResponse(429, "quota", false, mapOf("Retry-After" to "0")) else ok()
            }
        val connection = NvidiaNimConnection(config(transport), NimRequestCoordinator())
        try {
            assertNull(send(connection))
            assertNull(send(connection))
            assertEquals(requests[0], requests[1])
            val turns = NimProtocol.mapper.readTree(requests[2]).path("messages")
            assertEquals(listOf("user", "assistant", "user"), turns.map { it.path("role").asText() })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun `configuration errors are not retried and provider echo stays private`() {
        val calls = AtomicInteger()
        val transport =
            transport { _, _, _ ->
                calls.incrementAndGet()
                TransportResponse(404, "echo nvapi-secret and private request", false)
            }
        val connection = NvidiaNimConnection(config(transport), NimRequestCoordinator())
        try {
            val error = send(connection)
            assertEquals(1, calls.get())
            assertTrue(error!!.message!!.contains("404"))
            assertFalse(error.message!!.contains("nvapi-secret"))
        } finally {
            connection.stop()
        }
    }

    @Test
    fun `stop completes in flight request once without delivering a late chunk`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val exited = CountDownLatch(1)
        val transport =
            transport { _, _, _ ->
                entered.countDown()
                try {
                    release.await(3, TimeUnit.SECONDS)
                    ok()
                } finally {
                    exited.countDown()
                }
            }
        val connection = NvidiaNimConnection(config(transport), NimRequestCoordinator())
        val callbacks = AtomicInteger()
        val chunks = AtomicInteger()
        val done = CountDownLatch(1)
        try {
            connection.send("hello", onChunk = { chunks.incrementAndGet() }, onComplete = {
                callbacks.incrementAndGet()
                done.countDown()
            })
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            connection.stop()
            assertTrue(done.await(1, TimeUnit.SECONDS))
            release.countDown()
            assertTrue(exited.await(1, TimeUnit.SECONDS))
            assertEquals(1, callbacks.get())
            assertEquals(0, chunks.get())
        } finally {
            release.countDown()
            connection.stop()
        }
    }

    @Test
    fun `large retained history survives beyond the generic forty thousand character budget`() {
        val rootContext = "ROOT_CONTEXT_MARKER " + "site map entry\n".repeat(5000)
        val transport =
            transport { json, _, _ ->
                val messages = NimProtocol.mapper.readTree(json).path("messages")
                assertEquals(rootContext, messages[0].path("content").asText())
                assertEquals(5, messages.size())
                ok()
            }
        val connection = NvidiaNimConnection(config(transport), NimRequestCoordinator())
        try {
            assertNull(
                send(
                    connection,
                    history =
                        listOf(
                            ChatMessage("user", rootContext),
                            ChatMessage("assistant", "first answer"),
                            ChatMessage("user", "second question"),
                            ChatMessage("assistant", "second answer"),
                        ),
                ),
            )
        } finally {
            connection.stop()
        }
    }

    @Test
    fun `a failed turn followed by another UI prompt sends alternating roles`() {
        val requests = mutableListOf<String>()
        val transport =
            transport { json, _, _ ->
                requests.add(json)
                if (requests.size == 1) TransportResponse(500, "internal error", false, mapOf("Retry-After" to "0")) else ok()
            }
        val connection = NvidiaNimConnection(config(transport).copy(nvidiaNimOptions = NvidiaNimOptions(maxRetries = 0)), NimRequestCoordinator())
        try {
            assertTrue(send(connection) != null)
            assertNull(send(connection, history = listOf(ChatMessage("user", "earlier failed question"))))
            val messages = NimProtocol.mapper.readTree(requests[1]).path("messages")
            assertEquals(listOf("user"), messages.map { it.path("role").asText() })
            assertEquals("earlier failed question\n\nhello", messages[0].path("content").asText())
        } finally {
            connection.stop()
        }
    }

    @Test
    fun `persistent 500 reports attempt count shape and request id without provider echo`() {
        val calls = AtomicInteger()
        val transport =
            transport { _, _, _ ->
                calls.incrementAndGet()
                TransportResponse(500, "private echoed prompt and nvapi-secret", false, mapOf("Retry-After" to "0", "NVCF-REQID" to "123e4567-e89b-12d3-a456-426614174000"))
            }
        val connection = NvidiaNimConnection(config(transport), NimRequestCoordinator())
        try {
            val error = send(connection)
            assertEquals(3, calls.get())
            assertTrue(error!!.message!!.contains("after 3 attempt"))
            assertTrue(error.message!!.contains("roles=user"))
            assertTrue(error.message!!.contains("provider_request_id="))
            assertFalse(error.message!!.contains("private echoed prompt"))
            assertFalse(error.message!!.contains("nvapi-secret"))
        } finally {
            connection.stop()
        }
    }

    private fun config(transport: MontoyaHttpTransport) =
        BackendLaunchConfig(
            backendId = "nvidia-nim",
            displayName = "NVIDIA NIM",
            baseUrl = "https://integrate.api.nvidia.com/v1",
            model = NvidiaNimOptions.DEFAULT_MODEL,
            headers = mapOf("accept" to "text/event-stream", "Authorization" to "Bearer nvapi-test"),
            transport = transport,
        )

    private fun ok() = TransportResponse(200, """{"choices":[{"message":{"content":"answer"},"finish_reason":"stop"}]}""", true)

    private fun transport(response: (String, Map<String, String>, Long) -> TransportResponse): MontoyaHttpTransport {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doAnswer { call -> response(call.getArgument(2), call.getArgument(1), call.getArgument(3)) }
            .whenever(transport)
            .post(any(), any(), any(), any())
        return transport
    }

    private fun send(
        connection: AgentConnection,
        maxTokens: Int? = null,
        history: List<ChatMessage>? = null,
    ): Throwable? {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        connection.send("hello", history = history, onChunk = {}, onComplete = {
            error.set(it)
            done.countDown()
        }, maxOutputTokens = maxTokens)
        assertTrue(done.await(5, TimeUnit.SECONDS), "Request did not finish")
        return error.get()
    }
}
