package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.supervisor.ToolAnalysisSession
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class AiToolRuntimeTest {
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val supervisor = mock<AgentSupervisor>()

    @Test
    fun nimAnalyzeWorksWithNativeBurpAiDisabledAndPreservesOptions() {
        whenever(supervisor.isAiEnabled()).thenReturn(false)
        val connection = RecordingAnalysisConnection()
        whenever(supervisor.openToolAnalysisSession("nvidia-nim")).thenReturn(ToolAnalysisSession("nvidia-nim", connection, 1000))
        val result =
            McpToolExecutor.executeTool(
                "ai_analyze",
                """{"text":"Synthetic offline analysis","jsonMode":true,"maxOutputTokens":2000}""",
                context(),
                ToolCallOrigin.UserSlashCommand,
            )
        assertEquals("{\"ok\":true}", result)
        assertTrue(connection.jsonMode)
        assertEquals(2000, connection.maxTokens)
        assertFalse(connection.isAlive())
        verify(supervisor, never()).isAiEnabled()
    }

    @Test
    fun timeoutClosesTheIndependentConnection() {
        val connection = RecordingAnalysisConnection(complete = false)
        whenever(supervisor.openToolAnalysisSession("nvidia-nim")).thenReturn(ToolAnalysisSession("nvidia-nim", connection, 20))
        val result = executeAiAnalysis(AiAnalyzeInput("synthetic"), context())
        assertTrue(result.startsWith("Error:"))
        assertTrue(result.contains("timed out"))
        assertFalse(connection.isAlive())
    }

    @Test
    fun backendErrorsAreReturnedInsteadOfPartialAnalysis() {
        val connection = RecordingAnalysisConnection(failure = IllegalStateException("synthetic provider error"))
        whenever(supervisor.openToolAnalysisSession("nvidia-nim")).thenReturn(ToolAnalysisSession("nvidia-nim", connection, 1000))
        val result = executeAiAnalysis(AiAnalyzeInput("synthetic"), context())
        assertEquals("Error: AI backend: synthetic provider error", result)
        assertFalse(connection.isAlive())
    }

    @Test
    fun standaloneContextResolvesTheConfiguredBackend() {
        val connection = RecordingAnalysisConnection()
        whenever(supervisor.preferredBackendId()).thenReturn("nvidia-nim")
        whenever(supervisor.openToolAnalysisSession("nvidia-nim")).thenReturn(ToolAnalysisSession("nvidia-nim", connection, 1000))
        assertEquals("{\"ok\":true}", executeAiAnalysis(AiAnalyzeInput("synthetic"), context().copy(aiBackendId = null)))
    }

    @Test
    fun nimPassiveToolDoesNotRequireNativeBurpAi() {
        val scanner = mock<PassiveAiScanner>()
        val item = mock<ProxyHttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(item.request().url()).thenReturn("https://example.test/demo")
        whenever(api.proxy().history()).thenReturn(listOf(item))
        val converted = mock<HttpRequestResponse>()
        whenever(scanner.manualScan(any(), any())).thenAnswer { invocation ->
            assertEquals(listOf(converted), invocation.getArgument<List<HttpRequestResponse>>(0))
            1
        }
        mockStatic(HttpRequestResponse::class.java).use { factories ->
            factories
                .`when`<HttpRequestResponse> { HttpRequestResponse.httpRequestResponse(item.request(), item.response()) }
                .thenReturn(converted)
            val result = McpToolExecutor.executeTool("ai_passive_scan", "{}", context().copy(passiveScanner = scanner), ToolCallOrigin.UserSlashCommand)
            assertEquals("Queued 1 requests for AI passive scan.", result)
            verify(scanner).manualScan(any(), any())
        }
        verify(supervisor, never()).isAiEnabled()
    }

    @Test
    fun passiveToolStillFiltersByConfiguredMcpScope() {
        val scanner = mock<PassiveAiScanner>()
        val item = mock<ProxyHttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(item.request().url()).thenReturn("https://example.test/demo")
        whenever(api.proxy().history()).thenReturn(listOf(item))
        val result =
            McpToolExecutor.executeTool(
                "ai_passive_scan",
                "{}",
                context().copy(passiveScanner = scanner, scopeOnly = true),
                ToolCallOrigin.UserSlashCommand,
            )
        assertEquals("No matching requests found.", result)
        verify(scanner, never()).manualScan(any(), any())
    }

    private fun context(): McpToolContext =
        McpToolContext(
            api,
            PrivacyMode.OFF,
            false,
            "synthetic",
            McpToolCatalog.all().associate { it.id to true },
            false,
            McpToolCatalog.unsafeToolIds(),
            emptySet(),
            McpRequestLimiter(4),
            BurpSuiteEdition.PROFESSIONAL,
            32768,
            supervisor = supervisor,
            aiBackendId = "nvidia-nim",
        )
}

internal class RecordingAnalysisConnection(
    private val complete: Boolean = true,
    private val failure: Throwable? = null,
) : AgentConnection {
    private var alive = true
    var jsonMode = false
    var maxTokens: Int? = null

    override fun isAlive(): Boolean = alive

    override fun send(
        text: String,
        history: List<ChatMessage>?,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        systemPrompt: String?,
        jsonMode: Boolean,
        maxOutputTokens: Int?,
    ) {
        this.jsonMode = jsonMode
        maxTokens = maxOutputTokens
        if (complete) {
            onChunk("{\"ok\":true}")
            onComplete(failure)
        }
    }

    override fun stop() {
        alive = false
    }
}
