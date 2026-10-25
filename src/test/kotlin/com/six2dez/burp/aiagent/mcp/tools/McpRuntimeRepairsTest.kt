package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.audit.Audit
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
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

class McpRuntimeRepairsTest {
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    private fun context() = McpToolContext(api, PrivacyMode.OFF, false, "fixture", McpToolCatalog.all().associate { it.id to true }, true, McpToolCatalog.unsafeToolIds(), emptySet(), McpRequestLimiter(2), BurpSuiteEdition.PROFESSIONAL, 32768)

    @Test
    fun auditValidatesAllTargetsBeforeCreatingAnyTask() {
        val args = """{"mode":"active","requests":["GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"]}"""
        val result = McpToolExecutor.executeToolResult("scan_audit_start_mode", args, context())
        assertTrue(result.isError == true)
        verify(api.scanner(), never()).startAudit(any())
    }

    @Test
    fun auditAndCrawlRejectScopeViolationsBeforeAnyTaskExists() {
        val ctx = context().copy(scopeOnly = true)
        assertTrue(McpToolExecutor.executeToolResult("scan_audit_start_requests", """{"builtInConfiguration":"active","targetHostname":"fixture.test","targetPort":443,"usesHttps":true,"requests":["GET / HTTP/1.1\r\n\r\n"]}""", ctx).isError == true)
        assertTrue(McpToolExecutor.executeToolResult("scan_crawl_start", """{"seedUrls":["https://fixture.test/"]}""", ctx).isError == true)
        verify(api.scanner(), never()).startAudit(any())
        verify(api.scanner(), never()).startCrawl(any())
    }

    @Test
    fun successfulAuditQueuesThePreparedRequestAndReturnsAUsableTaskId() {
        val service = mock<HttpService>()
        val request = mock<HttpRequest>()
        val config = mock<AuditConfiguration>()
        val audit = mock<Audit>()
        whenever(audit.statusMessage()).thenReturn("Auditing")
        whenever(api.scanner().startAudit(config)).thenReturn(audit)
        val buffer = mock<burp.api.montoya.core.ByteArray>()
        val buffers = mockStatic(burp.api.montoya.core.ByteArray::class.java) { buffer }
        val services = mockStatic(HttpService::class.java)
        val requests = mockStatic(HttpRequest::class.java)
        val configs = mockStatic(AuditConfiguration::class.java)
        try {
            services.`when`<HttpService> { HttpService.httpService("fixture.test", 443, true) }.thenReturn(service)
            requests.`when`<HttpRequest> { HttpRequest.httpRequest(service, buffer) }.thenReturn(request)
            configs.`when`<AuditConfiguration> { AuditConfiguration.auditConfiguration(resolveAuditConfig("active")) }.thenReturn(config)
            val result = McpScannerTools.startAudit("active", listOf("GET / HTTP/1.1\n\n"), SendHttp1Request("", "fixture.test", 443, true), context())
            val id = result.substringAfter("id=").substringBefore(' ')
            assertEquals(audit, ScannerTaskRegistry.get(id))
            assertTrue(result.contains("queued_requests=1"))
            verify(audit).addRequest(request)
            ScannerTaskRegistry.remove(id)
        } finally {
            configs.close()
            requests.close()
            services.close()
            buffers.close()
        }
    }

    @Test
    fun requestBodyBytesSurviveHeaderNormalizationAndEmptyLengthIsCorrected() {
        val body = "a\nb\r\nтест"
        val fixed = normalizeHttpRequest("POST / HTTP/1.1\nContent-Length: 999\n\n$body")
        assertEquals(body, fixed.substringAfter("\r\n\r\n"))
        assertTrue(fixed.contains("Content-Length: ${body.toByteArray(Charsets.UTF_8).size}\r\n"))
        assertTrue(normalizeHttpRequest("POST / HTTP/1.1\nContent-Length: 99\n\n").contains("Content-Length: 0"))
    }

    @Test
    fun nestedExternalArgumentsRetainJsonTypes() {
        val values = McpToolExecutor.parseArgsMapOrEmpty("""{"nested":{"items":[1,true,null,{"name":"тест"}]},"empty":null}""")
        assertEquals(mapOf("items" to listOf(1L, true, null, mapOf("name" to "тест"))), values["nested"])
        assertEquals(null, values["empty"])
    }

    @Test
    fun utf8BoundsNeverSplitSurrogatesAndPreserveExternalBoundary() {
        val raw = "[EXTERNAL-TOOL-RESULT:fixture]\n" + "🧪я".repeat(100) + "\n[/EXTERNAL-TOOL-RESULT]"
        val output = context().copy(maxBodyBytes = 200).limitOutput(raw)
        assertTrue(output.endsWith("[/EXTERNAL-TOOL-RESULT]"))
        assertTrue(output.toByteArray(Charsets.UTF_8).size <= 200)
        assertFalse(output.contains('�'))
        assertEquals(
            "🧪",
            com.six2dez.burp.aiagent.util
                .utf8Prefix("🧪я", 5),
        )
        val builder = LimitedStringBuilder(5)
        builder.append("🧪я")
        val limited = builder.build()
        assertEquals(limited, String(limited.toByteArray(Charsets.UTF_8), Charsets.UTF_8))
    }

    @Test
    fun missingTasksAndMissingEditorAreErrors() {
        assertTrue(McpToolExecutor.executeToolResult("scan_task_status", """{"taskId":"missing"}""", context()).isError == true)
        McpEditorBridge.clear()
        assertTrue(McpToolExecutor.executeToolResult("editor_get", "{}", context()).isError == true)
    }

    @Test
    fun discoveryExplainsMissingRuntimeAndUsesRestrictedHistorySchema() {
        val ctx = context().copy(allowUnpreprocessedProxyHistory = false)
        val native = McpToolExecutor.functionTools(ctx)
        assertFalse(native.any { it.name == "ai_analyze" })
        assertFalse(native.first { it.name == "proxy_http_history" }.parametersJson.contains("includeUnpreprocessedResponse"))
        val description = McpToolExecutor.describeTools(ctx, true)
        assertTrue(description.contains("reason=AI runtime is not initialized"))
    }

    @Test
    fun scopeUsesTheConnectionHostAndHandlesIpv6AndAsteriskTargets() {
        assertEquals("https://[::1]/p?q=1", McpScopeFilter.deriveScopeUrl("::1", 443, true, "GET /p?q=1 HTTP/1.1"))
        assertEquals("https://fixture.test/", McpScopeFilter.deriveScopeUrl("fixture.test", 443, true, "OPTIONS * HTTP/1.1"))
        assertEquals("https://fixture.test/a?q=1", McpScopeFilter.deriveScopeUrl("fixture.test", 443, true, "GET http://other.test/a?q=1 HTTP/1.1"))
    }
}
