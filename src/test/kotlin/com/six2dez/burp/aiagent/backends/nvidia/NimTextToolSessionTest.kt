package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.JsonNode
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.AgentTurnEvent
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.FunctionResult
import com.six2dez.burp.aiagent.backends.FunctionTool
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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class NimTextToolSessionTest {
    private val payload = """{"tool":"proxy_http_history","args":{"count":20}}{"tool":"response_body_search","args":{"regex":"jquery.min.js"}}"""
    private val request =
        AgentChatRequest(
            "chat",
            "nvidia-nim",
            "Inspect synthetic captured evidence",
            traceId = "root-trace",
            systemPrompt = "Use enabled tools",
            tools = listOf(FunctionTool("proxy_http_history", "History", "{}"), FunctionTool("response_body_search", "Search", "{}")),
        )

    @Test
    fun nativeModeRecoversBothTextCallsAndCorrelatesBothResults() {
        val bodies = CopyOnWriteArrayList<JsonNode>()
        val connection =
            connection("auto") { body ->
                bodies.add(body)
                answer(if (bodies.size == 1) payload else "Completed")
            }
        try {
            val first = send(connection, request)
            val second = send(connection, request.copy(previousToolResult = FunctionResult(first.callId(), "RESULT_ONE")))
            assertEquals(1, bodies.size)
            assertTrue(second.events.any { it.detail.contains("no provider inference") })
            val final = send(connection, request.copy(previousToolResult = FunctionResult(second.callId(), "RESULT_TWO")))
            assertEquals("Completed", final.text)
            assertEquals(2, bodies.size)
            val messages = bodies.last().path("messages")
            assertEquals(listOf("system", "user", "assistant", "tool", "tool"), messages.map { it.path("role").asText() })
            assertEquals(listOf(first.callId(), second.callId()), messages.filter { it.path("role").asText() == "tool" }.map { it.path("tool_call_id").asText() })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun forcedTextModeDrainsTheBatchWithoutUnsupportedApiRoles() {
        val bodies = CopyOnWriteArrayList<JsonNode>()
        val connection =
            connection("text") { body ->
                bodies.add(body)
                answer(if (bodies.size == 1) payload else "Completed")
            }
        try {
            val first = send(connection, request)
            val second = send(connection, request.copy(previousToolResult = FunctionResult(first.callId(), "RESULT_ONE")))
            assertEquals(1, bodies.size)
            send(connection, request.copy(previousToolResult = FunctionResult(second.callId(), "RESULT_TWO")))
            val messages = bodies.last().path("messages")
            assertEquals(listOf("system", "user", "assistant", "user"), messages.map { it.path("role").asText() })
            val requestedIds = messages[2].path("content").asText()
            assertTrue(requestedIds.contains(first.callId()))
            assertTrue(requestedIds.contains(second.callId()))
            assertTrue(
                messages
                    .last()
                    .path("content")
                    .asText()
                    .contains("RESULT_ONE"),
            )
            assertTrue(
                messages
                    .last()
                    .path("content")
                    .asText()
                    .contains("RESULT_TWO"),
            )
            assertFalse(bodies.last().has("tools"))
        } finally {
            connection.stop()
        }
    }

    @Test
    fun unsupportedNativeFollowupKeepsEachResultOnceWhenSwitchingToText() {
        val bodies = CopyOnWriteArrayList<JsonNode>()
        val connection =
            connection("auto") { body ->
                bodies.add(body)
                when (bodies.size) {
                    1 -> answer(payload)
                    2 -> TransportResponse(400, """{"error":{"message":"tools are not supported","param":"tools"}}""", false)
                    else -> answer("Completed")
                }
            }
        try {
            val first = send(connection, request)
            val second = send(connection, request.copy(previousToolResult = FunctionResult(first.callId(), "RESULT_ONE")))
            val final = send(connection, request.copy(previousToolResult = FunctionResult(second.callId(), "RESULT_TWO")))
            assertTrue(final.events.any { it.stage == "fallback" })
            assertEquals(3, bodies.size)
            val text =
                bodies
                    .last()
                    .path("messages")
                    .last()
                    .path("content")
                    .asText()
            assertEquals(1, Regex("RESULT_ONE").findAll(text).count())
            assertEquals(1, Regex("RESULT_TWO").findAll(text).count())
            assertFalse(bodies.last().path("messages").any { it.path("role").asText() == "tool" })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun stoppingTextToolsSkipsRemainingMembersAndRequestsOnlyTheFinalAnswer() {
        val bodies = CopyOnWriteArrayList<JsonNode>()
        val connection =
            connection("text") { body ->
                bodies.add(body)
                answer(if (bodies.size == 1) payload else "Completed")
            }
        try {
            val first = send(connection, request)
            val final = send(connection, request.copy(tools = emptyList(), previousToolResult = FunctionResult(first.callId(), "Denied")))
            assertTrue(final.events.none { it.call != null })
            assertTrue(
                bodies
                    .last()
                    .path("messages")
                    .last()
                    .path("content")
                    .asText()
                    .contains("Not executed:"),
            )
            assertEquals(2, bodies.size)
        } finally {
            connection.stop()
        }
    }

    private data class Result(
        val text: String,
        val events: List<AgentTurnEvent>,
    ) {
        fun callId(): String = events.single { it.call != null }.call!!.id
    }

    private fun send(
        connection: NvidiaNimConnection,
        request: AgentChatRequest,
    ): Result {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        val text = StringBuilder()
        val events = CopyOnWriteArrayList<AgentTurnEvent>()
        connection.sendAgentTurn(request, { text.append(it) }, {
            error.set(it)
            done.countDown()
        }, events::add)
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertNull(error.get(), error.get()?.message)
        return Result(text.toString(), events.toList())
    }

    private fun connection(
        mode: String,
        response: (JsonNode) -> TransportResponse,
    ): NvidiaNimConnection {
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        doAnswer { invocation -> response(NimProtocol.mapper.readTree(invocation.getArgument<String>(2))) }.whenever(transport).post(any(), any(), any(), any())
        return NvidiaNimConnection(
            BackendLaunchConfig("nvidia-nim", "NIM", baseUrl = "https://example.test", model = "z-ai/glm-5.3", transport = transport, nvidiaNimOptions = NvidiaNimOptions(toolCallingMode = mode, maxRetries = 0)),
            NimRequestCoordinator(),
        )
    }

    private fun answer(text: String) = TransportResponse(200, NimProtocol.mapper.writeValueAsString(mapOf("choices" to listOf(mapOf("message" to mapOf("content" to text), "finish_reason" to "stop")))), true)
}
