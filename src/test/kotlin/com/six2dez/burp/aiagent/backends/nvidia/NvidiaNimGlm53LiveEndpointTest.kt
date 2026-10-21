package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.backends.AgentChatRequest
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.FunctionCall
import com.six2dez.burp.aiagent.backends.FunctionResult
import com.six2dez.burp.aiagent.backends.FunctionTool
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import com.six2dez.burp.aiagent.context.ChatContextStore
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
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

/** Opt-in compiled adapter check with a harmless synthetic function, outside the Burp runtime. */
@EnabledIfEnvironmentVariable(named = "NIM_GLM53_LIVE_TEST", matches = "true")
class NvidiaNimGlm53LiveEndpointTest {
    private val records = mutableListOf<Map<String, Any?>>()
    private val client =
        OkHttpClient
            .Builder()
            .callTimeout(240, TimeUnit.SECONDS)
            .readTimeout(240, TimeUnit.SECONDS)
            .connectTimeout(30, TimeUnit.SECONDS)
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    @Test
    fun `compiled GLM adapter executes a native function and correlates its result`() {
        val key = checkNotNull(System.getenv("NIM_LIVE_KEY")) { "Set NIM_LIVE_KEY for this opt-in check" }
        require(key.startsWith("nvapi-"))
        val connection =
            NvidiaNimConnection(
                BackendLaunchConfig(
                    "nvidia-nim",
                    "GLM live check",
                    baseUrl = NvidiaNimBackendFactory.DEFAULT_BASE_URL,
                    model = "z-ai/glm-5.3",
                    headers = mapOf("Authorization" to "Bearer $key"),
                    transport = transport(),
                    requestTimeoutSeconds = 240,
                    nvidiaNimOptions = NvidiaNimOptions(maxRetries = 0, maxTokens = 4096),
                ),
                NimRequestCoordinator(),
            )
        val schema = """{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"""
        val request =
            AgentChatRequest(
                "glm-live",
                "nvidia-nim",
                "Call echo_marker with value TOOL_RESULT_527. Do not answer without calling the function.",
                traceId = "glm-live-trace",
                tools = listOf(FunctionTool("echo_marker", "Return the supplied marker unchanged.", schema)),
            )
        try {
            val (_, call) = turn(connection, request)
            assertNotNull(call, "GLM must return an actual native function call")
            assertEquals("echo_marker", call!!.name)
            assertEquals(
                "TOOL_RESULT_527",
                NimProtocol.mapper
                    .readTree(call.argumentsJson)
                    .path("value")
                    .asText(),
            )
            val (answer, unexpectedCall) =
                turn(connection, request.copy(text = "The function returned TOOL_RESULT_527. Reply with only that value.", tools = emptyList(), previousToolResult = FunctionResult(call.id, """{"value":"TOOL_RESULT_527"}""")))
            assertNull(unexpectedCall)
            assertTrue(answer.contains("TOOL_RESULT_527"))
            assertEquals(2, records.size)
            assertTrue(records[1]["hasNativeResult"] as Boolean)
        } finally {
            connection.stop()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            val report = File("build/reports/nim-glm53-live.json")
            report.parentFile.mkdirs()
            report.writeText(NimProtocol.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapOf("scope" to "Compiled NIM adapter with an OkHttp bridge; not Burp runtime", "model" to "z-ai/glm-5.3", "requests" to records)))
        }
    }

    @Test
    fun glmSelectsAnActualBurpFunctionFromTheDefaultCatalog() {
        val key = checkNotNull(System.getenv("NIM_LIVE_KEY"))
        require(key.startsWith("nvapi-"))
        val context =
            McpToolContext(
                api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS),
                privacyMode = PrivacyMode.STRICT,
                determinismMode = false,
                hostSalt = "glm-catalog",
                toolToggles = McpToolCatalog.mergeWithDefaults(emptyMap()),
                unsafeEnabled = false,
                unsafeTools = McpToolCatalog.unsafeToolIds(),
                enabledUnsafeTools = emptySet(),
                limiter = McpRequestLimiter(1),
                edition = BurpSuiteEdition.PROFESSIONAL,
                maxBodyBytes = 262_144,
                chatContextStore = ChatContextStore(),
            )
        val functions = McpToolExecutor.functionTools(context)
        assertTrue(functions.size > 20)
        val connection =
            NvidiaNimConnection(
                BackendLaunchConfig(
                    "nvidia-nim",
                    "GLM catalog check",
                    baseUrl = NvidiaNimBackendFactory.DEFAULT_BASE_URL,
                    model = "z-ai/glm-5.3",
                    headers = mapOf("Authorization" to "Bearer $key"),
                    transport = transport(),
                    requestTimeoutSeconds = 240,
                    nvidiaNimOptions = NvidiaNimOptions(maxRetries = 0),
                ),
                NimRequestCoordinator(),
            )
        try {
            val (_, call) = turn(connection, AgentChatRequest("glm-catalog", "nvidia-nim", "Call scope_check for https://example.test/ before answering.", traceId = "catalog-trace", tools = functions))
            assertEquals("scope_check", call?.name)
            assertEquals(NvidiaNimOptions().maxTokens, records.single()["maxTokens"])
            assertEquals(
                "https://example.test/",
                NimProtocol.mapper
                    .readTree(call!!.argumentsJson)
                    .path("url")
                    .asText(),
            )
        } finally {
            connection.stop()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            val report = File("build/reports/nim-glm53-catalog-live.json")
            report.parentFile.mkdirs()
            report.writeText(NimProtocol.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mapOf("scope" to "Default Burp schemas, synthetic prompt; no tool execution", "toolCount" to functions.size, "requests" to records)))
        }
    }

    private fun transport(): MontoyaHttpTransport {
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        doAnswer { invocation ->
            val body = invocation.getArgument<String>(2)
            val payload = NimProtocol.mapper.readTree(body)
            val start = System.nanoTime()
            val request =
                Request
                    .Builder()
                    .url(invocation.getArgument<String>(0))
                    .post(body.toRequestBody("application/json; charset=utf-8".toMediaType()))
                    .apply { invocation.getArgument<Map<String, String>>(1).forEach { (name, value) -> header(name, value) } }
                    .build()
            client.newCall(request).execute().use { response ->
                records.add(
                    mapOf(
                        "status" to response.code,
                        "elapsedMs" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start),
                        "messages" to payload.path("messages").size(),
                        "hasNativeResult" to payload.path("messages").any { it.path("role").asText() == "tool" },
                        "toolChoice" to payload.path("tool_choice").asText(),
                        "reasoning" to payload.path("reasoning_effort").asText(),
                        "maxTokens" to payload.path("max_tokens").asInt(),
                    ),
                )
                TransportResponse(response.code, response.body.string(), response.isSuccessful, response.headers.toMap())
            }
        }.whenever(transport).post(any(), any(), any(), any())
        return transport
    }

    private fun turn(
        connection: NvidiaNimConnection,
        request: AgentChatRequest,
    ): Pair<String, FunctionCall?> {
        val done = CountDownLatch(1)
        val output = StringBuilder()
        val error = AtomicReference<Throwable?>()
        val call = AtomicReference<FunctionCall?>()
        connection.sendAgentTurn(request, { output.append(it) }, {
            error.set(it)
            done.countDown()
        }, { event -> event.call?.let { call.set(it) } })
        assertTrue(done.await(245, TimeUnit.SECONDS), "GLM exceeded the total request deadline")
        assertNull(error.get(), error.get()?.message)
        return output.toString() to call.get()
    }
}
