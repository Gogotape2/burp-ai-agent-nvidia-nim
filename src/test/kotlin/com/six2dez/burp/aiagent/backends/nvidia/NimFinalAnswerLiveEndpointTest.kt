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
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Inject the observed protocol failure, then submit only synthetic final-answer evidence to real NIM. */
@EnabledIfEnvironmentVariable(named = "NIM_FINAL_LIVE_TEST", matches = "true")
class NimFinalAnswerLiveEndpointTest {
    @Test
    fun realModelProducesAFinalAnswerAfterAnInjectedDisabledToolCall() {
        val key = checkNotNull(System.getenv("NIM_LIVE_KEY"))
        val client =
            OkHttpClient
                .Builder()
                .callTimeout(90, TimeUnit.SECONDS)
                .readTimeout(90, TimeUnit.SECONDS)
                .connectTimeout(15, TimeUnit.SECONDS)
                .followRedirects(false)
                .retryOnConnectionFailure(false)
                .build()
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        var posts = 0
        var liveStatus = 0
        doAnswer { invocation ->
            posts++
            if (posts <= 2) {
                TransportResponse(200, """{"choices":[{"message":{"content":null,"tool_calls":[{"id":"fixture_call","type":"function","function":{"name":"scope_check","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}""", true)
            } else {
                val json = invocation.getArgument<String>(2)
                val body = NimProtocol.mapper.readTree(json)
                assertFalse(body.has("tools"))
                assertFalse(body.has("tool_choice"))
                assertTrue(body.path("messages").none { it.has("tool_calls") || it.has("tool_call_id") || it.path("role").asText() == "tool" })
                val request =
                    Request
                        .Builder()
                        .url(invocation.getArgument<String>(0))
                        .header("Authorization", "Bearer $key")
                        .header("Accept", "application/json")
                        .post(json.toRequestBody("application/json".toMediaType()))
                        .build()
                client.newCall(request).execute().use { response ->
                    liveStatus = response.code
                    TransportResponse(response.code, response.body.string(), response.isSuccessful, response.headers.toMap())
                }
            }
        }.whenever(transport).post(any(), any(), any(), any())
        val connection =
            NvidiaNimConnection(
                BackendLaunchConfig(
                    "nvidia-nim",
                    "Final answer live test",
                    baseUrl = "https://integrate.api.nvidia.com",
                    model = NvidiaNimOptions.DEFAULT_MODEL,
                    headers = mapOf("Authorization" to "Bearer $key"),
                    transport = transport,
                    requestTimeoutSeconds = 90,
                    nvidiaNimOptions = NvidiaNimOptions(maxTokens = 4096, maxRetries = 0),
                ),
                NimRequestCoordinator(),
            )
        val initial =
            AgentChatRequest(
                "final-live",
                "nvidia-nim",
                "Summarize the observed synthetic response in one short sentence; do not infer a vulnerability.",
                traceId = "final-live-trace",
                tools = listOf(FunctionTool("scope_check", "Synthetic scope fixture", """{"type":"object","properties":{}}""")),
            )
        val started = System.nanoTime()
        try {
            turn(connection, initial)
            val (answer, events) = turn(connection, initial.copy(tools = emptyList(), previousToolResult = FunctionResult("fixture_call", "Synthetic observation: HTTP/1.1 200 OK; Content-Type: application/json; {\"status\":\"ok\",\"items\":3}")))
            assertEquals(3, posts)
            assertEquals(200, liveStatus)
            assertTrue(events.any { it.stage == "final_answer_retry" })
            assertTrue(events.none { it.call != null })
            assertTrue(answer.contains("200") || answer.contains("ok", true))
            writeResult(key, liveStatus, events, answer, started)
        } finally {
            connection.stop()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }

    private fun writeResult(
        key: String,
        liveStatus: Int,
        events: List<AgentTurnEvent>,
        answer: String,
        started: Long,
    ) {
        val result =
            mapOf(
                "scope" to "Injected disabled-tool provider response, then a real compiled-adapter final-answer repair; synthetic evidence only, not Burp runtime",
                "model" to NvidiaNimOptions.DEFAULT_MODEL,
                "httpStatus" to liveStatus,
                "networkCalls" to 1,
                "repairEvents" to events.count { it.stage == "final_answer_retry" },
                "extraToolsExecuted" to 0,
                "elapsedMs" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started),
                "answer" to answer,
                "passed" to true,
            )
        val text = NimProtocol.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(result)
        check(!text.contains(key))
        File("build/reports/nim-final-answer-live.json").apply {
            parentFile.mkdirs()
            writeText(text)
        }
    }

    private fun turn(
        connection: NvidiaNimConnection,
        request: AgentChatRequest,
    ): Pair<String, List<AgentTurnEvent>> {
        val done = CountDownLatch(1)
        val error = AtomicReference<Throwable?>()
        val output = StringBuilder()
        val events = mutableListOf<AgentTurnEvent>()
        connection.sendAgentTurn(request, { output.append(it) }, {
            error.set(it)
            done.countDown()
        }, { events.add(it) })
        assertTrue(done.await(95, TimeUnit.SECONDS), "Final-answer live turn exceeded its deadline")
        assertNull(error.get(), error.get()?.message)
        return output.toString() to events.toList()
    }
}
