package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.jupiter.api.Assertions.assertEquals
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

/** Opt-in real API check. The test-only HTTP bridge does not claim to exercise Burp networking. */
@EnabledIfEnvironmentVariable(named = "NIM_LIVE_TEST", matches = "true")
class NvidiaNimLiveEndpointTest {
    @Test
    fun `compiled adapter retains a large multilingual history and parses structured output`() {
        val key = checkNotNull(System.getenv("NIM_LIVE_KEY")) { "Set NIM_LIVE_KEY for this opt-in check" }
        require(key.startsWith("nvapi-"))
        val client =
            OkHttpClient
                .Builder()
                .callTimeout(90, TimeUnit.SECONDS)
                .readTimeout(90, TimeUnit.SECONDS)
                .connectTimeout(60, TimeUnit.SECONDS)
                .followRedirects(false)
                .retryOnConnectionFailure(false)
                .build()
        val records = mutableListOf<Map<String, Any?>>()
        val transport = liveTransport(client, records)
        val connection =
            NvidiaNimConnection(
                BackendLaunchConfig(
                    backendId = "nvidia-nim",
                    displayName = "NIM live check",
                    baseUrl = NvidiaNimBackendFactory.DEFAULT_BASE_URL,
                    model = NvidiaNimOptions.DEFAULT_MODEL,
                    headers = mapOf("Authorization" to "Bearer $key"),
                    transport = transport,
                    requestTimeoutSeconds = 90,
                    nvidiaNimOptions = NvidiaNimOptions(maxRetries = 0),
                ),
                NimRequestCoordinator(),
            )
        try {
            val context = (0 until 1200).joinToString("\n") { "GET https://example.test/catalog/$it status=200 label=Проверка" }
            assertTrue(context.length > 40_000)
            assertEquals("nim_context_731", turn(connection, "$context\nRESULT_MARKER=nim_context_731\nReturn only the value of RESULT_MARKER."))
            assertEquals("nim_context_731", turn(connection, "What was RESULT_MARKER in my first message? Return only its value."))
            assertTrue(records[1]["inputChars"] as Int > 40_000)
            val json = turn(connection, "Return a JSON object with key status and value ok.", jsonMode = true)
            assertEquals(
                "ok",
                NimProtocol.mapper
                    .readTree(json)
                    .path("status")
                    .asText(),
            )
            assertTrue(connection.lastTokenUsage()!!.inputTokens > 0)
        } finally {
            connection.stop()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
            val report = File("build/reports/nim-live.json")
            report.parentFile.mkdirs()
            report.writeText(
                NimProtocol.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(
                    mapOf(
                        "scope" to "Compiled NIM adapter using a test-only OkHttp bridge; not a Burp runtime test",
                        "requests" to records,
                    ),
                ),
            )
        }
    }

    private fun liveTransport(
        client: OkHttpClient,
        records: MutableList<Map<String, Any?>>,
    ): MontoyaHttpTransport {
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
                        "model" to payload.path("model").asText(),
                        "status" to response.code,
                        "messages" to payload.path("messages").size(),
                        "inputChars" to payload.path("messages").sumOf { it.path("content").asText().length },
                        "elapsedMs" to TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start),
                        "reasoning" to payload.path("reasoning_effort").asText(),
                    ),
                )
                TransportResponse(response.code, response.body.string(), response.isSuccessful, response.headers.toMap())
            }
        }.whenever(transport).post(any(), any(), any(), any())
        return transport
    }

    private fun turn(
        connection: NvidiaNimConnection,
        prompt: String,
        jsonMode: Boolean = false,
    ): String {
        val done = CountDownLatch(1)
        val output = StringBuilder()
        val error = AtomicReference<Throwable?>()
        connection.send(prompt, onChunk = { output.append(it) }, onComplete = {
            error.set(it)
            done.countDown()
        }, jsonMode = jsonMode)
        assertTrue(done.await(95, TimeUnit.SECONDS), "Live request exceeded its deadline")
        assertNull(error.get(), error.get()?.message)
        return output.toString().trim()
    }
}
