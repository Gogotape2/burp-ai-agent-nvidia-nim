package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
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
import org.junit.jupiter.api.Assertions.assertNotNull
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

class NimFunctionCallingTest {
    private val functions = listOf(FunctionTool("scope_check", "Check scope", """{"properties":{"url":{"type":"string"}},"required":["url"]}"""))

    private fun request() = AgentChatRequest("chat-native", "nvidia-nim", "Inspect the selected issue", traceId = "trace-native", tools = functions)

    @Test
    fun nativeBatchUsesCorrelatedToolRolesAndDrainsBeforeAnotherInference() {
        val bodies = CopyOnWriteArrayList<com.fasterxml.jackson.databind.JsonNode>()
        val connection =
            connection { json ->
                val body = NimProtocol.mapper.readTree(json)
                bodies.add(body)
                if (bodies.size == 1) nativeBatch() else answer()
            }
        try {
            val first = send(connection, request())
            assertNull(first.error)
            assertEquals(
                "call_a",
                first.events
                    .single { it.call != null }
                    .call
                    ?.id,
            )
            assertTrue(first.text.contains("scope_check"))
            assertEquals(
                "object",
                bodies[0]
                    .path("tools")[0]
                    .path("function")
                    .path("parameters")
                    .path("type")
                    .asText(),
            )
            assertEquals("auto", bodies[0].path("tool_choice").asText())
            val second = send(connection, request().copy(text = "internal followup must not be sent as a user role", previousToolResult = FunctionResult("call_a", "in_scope=true")))
            assertNull(second.error)
            assertEquals(
                "call_b",
                second.events
                    .single { it.call != null }
                    .call
                    ?.id,
            )
            assertEquals(1, bodies.size, "A queued function must not start another provider inference")
            val third = send(connection, request().copy(text = "another internal followup", previousToolResult = FunctionResult("call_b", "in_scope=false")))
            assertNull(third.error)
            assertEquals("finished", third.text)
            assertEquals(2, bodies.size)
            val messages = bodies[1].path("messages")
            assertEquals(listOf("user", "assistant", "tool", "tool"), messages.map { it.path("role").asText() })
            assertEquals(listOf("call_a", "call_b"), messages.filter { it.path("role").asText() == "tool" }.map { it.path("tool_call_id").asText() })
            assertFalse(messages.toString().contains("internal followup"))
        } finally {
            connection.stop()
        }
    }

    @Test
    fun disablingToolsCompletesUnusedBatchMembersWithoutExecutingThem() {
        val bodies = CopyOnWriteArrayList<com.fasterxml.jackson.databind.JsonNode>()
        val connection =
            connection { json ->
                bodies.add(NimProtocol.mapper.readTree(json))
                if (bodies.size == 1) nativeBatch() else answer()
            }
        try {
            assertNull(send(connection, request()).error)
            val final = send(connection, request().copy(tools = emptyList(), previousToolResult = FunctionResult("call_a", "not available")))
            assertNull(final.error)
            assertTrue(final.events.none { it.call != null })
            assertEquals("none", bodies.last().path("tool_choice").asText())
            assertTrue(
                bodies
                    .last()
                    .path("messages")
                    .last()
                    .path("content")
                    .asText()
                    .startsWith("Not executed:"),
            )
        } finally {
            connection.stop()
        }
    }

    @Test
    fun ignoredToolChoiceNoneGetsOneTextOnlyFinalAnswerWithoutExecutingMoreCalls() {
        val bodies = CopyOnWriteArrayList<com.fasterxml.jackson.databind.JsonNode>()
        val connection =
            connection { json ->
                bodies.add(NimProtocol.mapper.readTree(json))
                when (bodies.size) {
                    1, 2 -> nativeBatch().copy(body = nativeBatch().body.dropLast(1) + ",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}")
                    else -> answer().copy(body = answer().body.dropLast(1) + ",\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":3}}")
                }
            }
        try {
            assertNull(send(connection, request()).error)
            val final = send(connection, request().copy(tools = emptyList(), previousToolResult = FunctionResult("call_a", "OBSERVED_EVIDENCE_MARKER")))
            assertNull(final.error)
            assertEquals("finished", final.text)
            assertEquals(3, bodies.size)
            assertTrue(final.events.none { it.call != null })
            assertTrue(final.events.any { it.stage == "final_answer_retry" })
            val repair = bodies.last()
            assertFalse(repair.has("tools"))
            assertFalse(repair.has("tool_choice"))
            assertTrue(repair.path("messages").all { it.path("role").asText() in setOf("system", "user", "assistant") && !it.has("tool_calls") && !it.has("tool_call_id") })
            assertTrue(repair.path("messages").toString().contains("OBSERVED_EVIDENCE_MARKER"))
            assertTrue(repair.path("messages").toString().contains("Not executed:"))
            assertEquals(30, connection.lastTokenUsage()?.inputTokens)
            assertEquals(5, connection.lastTokenUsage()?.outputTokens)
        } finally {
            connection.stop()
        }
    }

    @Test
    fun repeatedDisabledToolCallsStopAfterOneFinalAnswerRepair() {
        val bodies = CopyOnWriteArrayList<String>()
        val connection =
            connection { json ->
                bodies.add(json)
                nativeBatch()
            }
        try {
            assertNull(send(connection, request()).error)
            val final = send(connection, request().copy(tools = emptyList(), previousToolResult = FunctionResult("call_a", "in_scope=true")))
            assertEquals(3, bodies.size, "The final-answer repair is bounded to one provider inference")
            assertNotNull(final.error)
            assertTrue(
                final.error!!
                    .message
                    .orEmpty()
                    .contains("final-answer"),
            )
            assertTrue(final.events.none { it.call != null })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun textCallInsteadOfARepairedFinalAnswerIsNeverReturnedAsAnInstruction() {
        val bodies = CopyOnWriteArrayList<String>()
        val connection =
            connection { json ->
                bodies.add(json)
                if (bodies.size <= 2) nativeBatch() else answer().copy(body = """{"choices":[{"message":{"content":"{\"tool\":\"scope_check\",\"args\":{}}"},"finish_reason":"stop"}]}""")
            }
        try {
            assertNull(send(connection, request()).error)
            val final = send(connection, request().copy(tools = emptyList(), previousToolResult = FunctionResult("call_a", "in_scope=true")))
            assertEquals(3, bodies.size)
            assertNotNull(final.error)
            assertTrue(final.text.isEmpty())
            assertTrue(final.events.none { it.call != null })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun autoFallsBackOnlyOnExplicitUnsupportedToolsAndRemembersThatForTheConnection() {
        val bodies = CopyOnWriteArrayList<com.fasterxml.jackson.databind.JsonNode>()
        val connection =
            connection { json ->
                bodies.add(NimProtocol.mapper.readTree(json))
                if (bodies.size == 1) TransportResponse(400, """{"error":{"param":"tools","message":"tools are not supported by this model"}}""", false) else answer()
            }
        try {
            val first = send(connection, request())
            assertNull(first.error)
            assertTrue(first.events.any { it.stage == "fallback" })
            assertFalse(bodies[1].has("tools"))
            assertTrue(bodies[1].path("messages").toString().contains("scope_check"))
            assertNull(send(connection, request().copy(traceId = "new-root")).error)
            assertEquals(3, bodies.size)
            assertFalse(bodies.last().has("tools"))
        } finally {
            connection.stop()
        }
    }

    @Test
    fun nativeModeDoesNotSilentlyDowngradeAndOrdinary400DoesNotTriggerFallback() {
        for ((mode, body) in listOf("native" to """{"error":{"param":"tools","message":"tools unsupported"}}""", "auto" to """{"error":{"message":"invalid model parameters"}}""")) {
            val bodies = CopyOnWriteArrayList<String>()
            val connection =
                connection(NvidiaNimOptions(toolCallingMode = mode)) { json ->
                    bodies.add(json)
                    TransportResponse(400, body, false)
                }
            try {
                val result = send(connection, request())
                assertNotNull(result.error)
                assertEquals(1, bodies.size)
                assertTrue(result.events.none { it.stage == "fallback" })
            } finally {
                connection.stop()
            }
        }
    }

    @Test
    fun malformedNativeArgumentsNeverReachTheExecutionCallback() {
        val connection = connection { nativeBatch().copy(body = nativeBatch().body.replace("{}", "{")) }
        try {
            val result = send(connection, request())
            assertNotNull(result.error)
            assertTrue(result.events.none { it.call != null })
        } finally {
            connection.stop()
        }
    }

    @Test
    fun inputBudgetRejectsOversizedCurrentRequestBeforeHttp() {
        val bodies = CopyOnWriteArrayList<String>()
        val connection =
            connection(NvidiaNimOptions(inputTokenBudget = 4096)) { json ->
                bodies.add(json)
                answer()
            }
        try {
            val result = send(connection, request().copy(text = "evidence".repeat(20_000)))
            assertNotNull(result.error)
            assertTrue(bodies.isEmpty())
        } finally {
            connection.stop()
        }
    }

    @Test
    fun retryProgressContainsStagesWithoutProviderBodyOrCredentials() {
        val bodies = CopyOnWriteArrayList<String>()
        val connection =
            connection { json ->
                bodies.add(json)
                if (bodies.size == 1) TransportResponse(500, "PRIVATE_PROVIDER_ECHO", false, mapOf("Retry-After" to "0")) else answer()
            }
        try {
            val result = send(connection, request())
            assertNull(result.error)
            assertTrue(result.events.map { it.stage }.containsAll(listOf("queue", "provider", "retry")))
            assertFalse(result.events.toString().contains("PRIVATE_PROVIDER_ECHO"))
            assertFalse(result.events.toString().contains("fixture-credential"))
        } finally {
            connection.stop()
        }
    }

    private data class Result(
        val text: String,
        val error: Throwable?,
        val events: List<AgentTurnEvent>,
    )

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
        }, { events.add(it) })
        assertTrue(done.await(5, TimeUnit.SECONDS))
        return Result(text.toString(), error.get(), events.toList())
    }

    private fun connection(
        options: NvidiaNimOptions = NvidiaNimOptions(),
        response: (String) -> TransportResponse,
    ): NvidiaNimConnection {
        val api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)
        val transport = spy(MontoyaHttpTransport(api))
        doAnswer { call -> response(call.getArgument(2)) }.whenever(transport).post(any(), any(), any(), any())
        return NvidiaNimConnection(
            BackendLaunchConfig("nvidia-nim", "NVIDIA NIM", baseUrl = "https://example.test", model = NvidiaNimOptions.DEFAULT_MODEL, transport = transport, headers = mapOf("Authorization" to "Bearer fixture-credential"), nvidiaNimOptions = options),
            NimRequestCoordinator(),
        )
    }

    private fun answer() = TransportResponse(200, """{"choices":[{"message":{"content":"finished"},"finish_reason":"stop"}]}""", true)

    private fun nativeBatch() =
        TransportResponse(
            200,
            """
            {"choices":[{"message":{"content":null,"tool_calls":[
              {"id":"call_a","type":"function","function":{"name":"scope_check","arguments":"{}"}},
              {"id":"call_b","type":"function","function":{"name":"scope_check","arguments":"{}"}}
            ]},"finish_reason":"tool_calls"}]}
            """.trimIndent(),
            true,
        )
}
