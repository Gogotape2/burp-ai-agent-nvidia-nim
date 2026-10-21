package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
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

class NimRestrictionTest {
    @Test
    fun accessPolicyAndRegionalRefusalsAreClassifiedWithoutEchoingTheBody() {
        val messages = mapOf("Missing Public API Endpoints entitlement" to "account/model", "Request violates content policy" to "terms/content-policy", "Not available in your region" to "regional/legal")
        for ((reason, category) in messages) {
            val body = NimProtocol.mapper.writeValueAsString(mapOf("error" to mapOf("message" to "$reason; PRIVATE_FIXTURE nvapi-hidden")))
            val response = TransportResponse(451, body, false)
            val message = NimErrorInfo.httpError(response, 1, "shape").message!!
            assertTrue(message.contains(category))
            assertFalse(message.contains("PRIVATE_FIXTURE"))
            assertFalse(message.contains("nvapi-hidden"))
            assertFalse(message.contains("server error"))
            assertFalse(message.contains("Retry after a pause"))
        }
        assertTrue(NimProviderRestriction.describe(TransportResponse(451, "", false)).contains("exact reason was not identified"))
        assertTrue(NimProviderRestriction.describe(TransportResponse(451, """{"detail":"Request violates terms of service"}""", false)).contains("terms/content-policy"))
    }

    @Test
    fun a451IsNeverRetriedAndEarlierTransientStatusesAreReported() {
        for (statuses in listOf(listOf(451), listOf(500, 451))) {
            val calls = AtomicInteger()
            val connection =
                connection {
                    val status = statuses[calls.getAndIncrement()]
                    TransportResponse(status, if (status == 451) """{"error":{"message":"Request violates content policy; PRIVATE_FIXTURE"}}""" else "temporary", false, mapOf("Retry-After" to "0"))
                }
            try {
                val done = CountDownLatch(1)
                val error = AtomicReference<Throwable?>()
                val text = StringBuilder()
                connection.sendAgentTurn(AgentChatRequest("chat", "nvidia-nim", "Synthetic request"), { text.append(it) }, {
                    error.set(it)
                    done.countDown()
                }, {})
                assertTrue(done.await(5, TimeUnit.SECONDS))
                assertNotNull(error.get())
                assertEquals(statuses.size, calls.get())
                assertTrue(error.get()!!.message!!.contains("http_statuses=${statuses.joinToString(",")}"))
                assertFalse(error.get()!!.message!!.contains("PRIVATE_FIXTURE"))
                assertTrue(text.isEmpty())
            } finally {
                connection.stop()
            }
        }
        assertFalse(NimHttpStatus.retryable(451))
    }

    @Test
    fun requestMetadataShowsProtocolAndModelButDoesNotExposePromptOrCredentials() {
        val request = AgentChatRequest("chat", "nvidia-nim", "PRIVATE_FIXTURE")
        val config = BackendLaunchConfig("nvidia-nim", "NIM", model = "z-ai/glm-5.3", nvidiaNimOptions = NvidiaNimOptions(maxTokens = 32768))
        val messages = listOf(mapOf<String, Any?>("role" to "user", "content" to "PRIVATE_FIXTURE"))
        val shape = NimRequestShape.describe(config, request, messages, true, 100)
        assertTrue(shape.contains("model=z-ai/glm-5.3 protocol=native"))
        assertTrue(shape.contains("max_tokens=32768"))
        assertFalse(shape.contains("PRIVATE_FIXTURE"))
        assertFalse(NimRequestShape.describe(config.copy(model = "vendor/nvapi-hidden"), request, messages, false, 100).contains("nvapi-hidden"))
    }

    private fun connection(response: () -> TransportResponse): NvidiaNimConnection {
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        doAnswer { response() }.whenever(transport).post(any(), any(), any(), any())
        return NvidiaNimConnection(BackendLaunchConfig("nvidia-nim", "NIM", baseUrl = "https://example.test", model = "z-ai/glm-5.3", transport = transport), NimRequestCoordinator())
    }
}
