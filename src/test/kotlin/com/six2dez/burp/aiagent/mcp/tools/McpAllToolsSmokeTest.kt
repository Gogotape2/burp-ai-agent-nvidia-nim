package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.audit.Audit
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.context.ChatContextStore
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.supervisor.ToolAnalysisSession
import com.six2dez.burp.aiagent.web.WebResearchClient
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.mockito.Answers
import org.mockito.MockedStatic
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Optional
import javax.swing.SwingUtilities

/** Execute every production dispatcher with synthetic Montoya services. No live Burp or target traffic. */
class McpAllToolsSmokeTest {
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val request = mock<HttpRequest>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val response = mock<HttpResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val rr = mock<HttpRequestResponse>()
    private val audit = mock<Audit>()
    private val supervisor = mock<AgentSupervisor>()
    private val scanner = mock<PassiveAiScanner>()
    private val registry = mock<BackendRegistry>()
    private val logger = AiRequestLogger()
    private val raw = "GET / HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
    private val mapper = jacksonObjectMapper()

    @ParameterizedTest
    @EnumSource(value = PrivacyMode::class, names = ["OFF", "BALANCED"])
    fun everyCatalogToolExecutesItsDocumentedOperation(privacyMode: PrivacyMode) {
        val service = mock<HttpService>()
        val bytes = mock<ByteArray>()
        val options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        val template = mock<HttpRequestTemplate>()
        val factories =
            listOf(
                factory(request),
                factory(response),
                factory(service),
                factory(bytes),
                factory(options),
                factory(template),
                factory(mock<HttpHeader>()),
                factory(mock<AuditConfiguration>()),
                factory(mock<CrawlConfiguration>()),
                factory(mock<AuditIssue>()),
            )
        val store = ChatContextStore()
        val snapshot = store.put("Synthetic context")
        val taskId = ScannerTaskRegistry.put(audit)
        try {
            prepareServices(service, bytes, template)
            val editor = bindEditor()
            val web = mock<WebResearchClient>()
            whenever(web.search(any())).thenReturn("Synthetic search result")
            whenever(web.fetch(any())).thenReturn("Synthetic documentation")
            val context = context(privacyMode, store, web)
            val cases = inputs(snapshot, taskId)
            assertEquals((McpToolCatalog.all().map { it.id }.toSet() - ActiveToolHandlers.ids), cases.keys, "Every catalog operation must have an executable fixture")
            val executed = mutableSetOf<String>()
            var collaboratorHandle = ""
            for ((name, input) in cases) {
                val arguments = if (name == "collaborator_poll") mapOf("clientId" to collaboratorHandle) else input
                val result = McpToolExecutor.executeToolResult(name, mapper.writeValueAsString(arguments), context)
                val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
                assertFalse(result.isError == true, "$name failed: $text")
                assertFalse(text.contains("not initialized"), name)
                if (name == "collaborator_generate") collaboratorHandle = text.substringAfter("client_id=").substringBefore('\n')
                if (name == "editor_set") {
                    org.mockito.kotlin
                        .verify(editor)
                        .setRequest(request)
                }
                executed.add(name)
            }
            assertEquals(62, executed.size)
            assertTrue(collaboratorHandle.startsWith("collab_"))
            org.mockito.kotlin
                .verify(api.http(), org.mockito.kotlin.times(2))
                .sendRequest(request, options)
            org.mockito.kotlin
                .verify(api.repeater(), org.mockito.kotlin.times(2))
                .sendToRepeater(request, null)
            org.mockito.kotlin
                .verify(api.siteMap())
                .add(any<AuditIssue>())
        } finally {
            factories.asReversed().forEach { it.close() }
            McpEditorBridge.clear()
            ScannerTaskRegistry.clear()
            CollaboratorRegistry.clear()
            logger.shutdown()
        }
    }

    private fun context(
        privacyMode: PrivacyMode,
        store: ChatContextStore,
        web: WebResearchClient,
    ) = McpToolContext(
        api,
        privacyMode,
        false,
        "fixture",
        McpToolCatalog.all().associate { it.id to true },
        true,
        McpToolCatalog.unsafeToolIds(),
        emptySet(),
        McpRequestLimiter(2),
        BurpSuiteEdition.PROFESSIONAL,
        32768,
        supervisor = supervisor,
        passiveScanner = scanner,
        backendRegistry = registry,
        aiRequestLogger = logger,
        aiBackendId = "nvidia-nim",
        chatContextStore = store,
        webResearchClient = web,
    )

    private inline fun <reified T : Any> factory(value: T): MockedStatic<T> = mockStatic(T::class.java) { value }

    private fun prepareServices(
        service: HttpService,
        bytes: ByteArray,
        template: HttpRequestTemplate,
    ) {
        whenever(api.burpSuite().version().name()).thenReturn("Fixture Burp")
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.scope().isInScope(any())).thenReturn(true)
        whenever(request.httpService()).thenReturn(service)
        whenever(request.url()).thenReturn("https://fixture.test/")
        whenever(request.method()).thenReturn("GET")
        whenever(request.path()).thenReturn("/")
        whenever(request.toString()).thenReturn(raw)
        whenever(request.bodyToString()).thenReturn("fixture")
        whenever(response.statusCode()).thenReturn(200.toShort())
        whenever(response.bodyToString()).thenReturn("fixture")
        whenever(request.body()).thenReturn(bytes)
        whenever(response.body()).thenReturn(bytes)
        whenever(bytes.length()).thenReturn(7)
        whenever(bytes.toString()).thenReturn("fixture")
        whenever(rr.request()).thenReturn(request)
        whenever(rr.response()).thenReturn(response)
        whenever(rr.toString()).thenReturn("HTTP/1.1 200 OK\r\n\r\nfixture")
        whenever(api.http().sendRequest(any<HttpRequest>(), any<RequestOptions>())).thenReturn(rr)
        whenever(api.burpSuite().exportProjectOptionsAsJson()).thenReturn("{}")
        whenever(api.burpSuite().exportUserOptionsAsJson()).thenReturn("{}")
        whenever(api.utilities().urlUtils().encode("a b")).thenReturn("a%20b")
        whenever(api.utilities().urlUtils().decode("a%20b")).thenReturn("a b")
        whenever(api.utilities().base64Utils().encodeToString("fixture")).thenReturn("Zml4dHVyZQ==")
        whenever(api.utilities().base64Utils().decode("Zml4dHVyZQ==")).thenReturn(bytes)
        whenever(api.utilities().randomUtils().randomString(4, "ab")).thenReturn("abba")
        whenever(api.scanner().startAudit(any())).thenReturn(audit)
        whenever(audit.statusMessage()).thenReturn("Queued")
        whenever(template.insertionPointOffsets()).thenReturn(emptyList())
        val payload = mock<CollaboratorPayload>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(payload.toString()).thenReturn("payload.fixture.invalid")
        whenever(api.collaborator().createClient().generatePayload()).thenReturn(payload)
        whenever(supervisor.openToolAnalysisSession("nvidia-nim")).thenReturn(ToolAnalysisSession("nvidia-nim", RecordingAnalysisConnection(), 1000))
        whenever(supervisor.status()).thenReturn(AgentSupervisor.Status("Idle", null))
        whenever(registry.listAllBackendIds()).thenReturn(listOf("nvidia-nim"))
    }

    private fun bindEditor(): MessageEditorHttpRequestResponse {
        val editor = mock<MessageEditorHttpRequestResponse>()
        whenever(editor.requestResponse()).thenAnswer {
            assertTrue(SwingUtilities.isEventDispatchThread(), "Editor must only be accessed on EDT")
            rr
        }
        whenever(editor.selectionContext()).thenReturn(MessageEditorHttpRequestResponse.SelectionContext.REQUEST)
        val event = mock<ContextMenuEvent>()
        whenever(event.messageEditorRequestResponse()).thenReturn(Optional.of(editor))
        whenever(event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST)).thenReturn(true)
        SwingUtilities.invokeAndWait { McpEditorBridge.bind(event) }
        return editor
    }

    private fun inputs(
        snapshot: String,
        taskId: String,
    ): Map<String, Map<String, Any?>> {
        val target = mapOf("targetHostname" to "fixture.test", "targetPort" to 443, "usesHttps" to true)
        val requestArgs = target + mapOf("content" to raw)
        val page = mapOf("count" to 5, "offset" to 0)
        val result =
            linkedMapOf<String, Map<String, Any?>>(
                "web_search" to mapOf("query" to "Apache 2.4 CVE"),
                "web_fetch" to mapOf("url" to "https://example.org/docs"),
                "context_read" to mapOf("id" to snapshot),
                "status" to emptyMap(),
                "http1_request" to requestArgs,
                "http2_request" to (target + mapOf("pseudoHeaders" to mapOf("method" to "GET", "path" to "/", "scheme" to "https", "authority" to "fixture.test"), "headers" to emptyMap<String, String>(), "requestBody" to "")),
                "repeater_tab" to requestArgs,
                "repeater_tab_with_payload" to (requestArgs + mapOf("replacements" to mapOf("fixture" to "fixture"))),
                "intruder" to requestArgs,
                "intruder_prepare" to requestArgs,
                "insertion_points" to mapOf("content" to raw),
                "params_extract" to mapOf("content" to raw),
                "diff_requests" to mapOf("requestA" to "a", "requestB" to "b"),
                "request_parse" to mapOf("content" to raw),
                "response_parse" to mapOf("content" to "HTTP/1.1 200 OK\r\n\r\n"),
                "find_reflected" to mapOf("request" to raw, "response" to "fixture"),
                "comparer_send" to mapOf("items" to listOf("a", "b")),
                "url_encode" to mapOf("content" to "a b"),
                "url_decode" to mapOf("content" to "a%20b"),
                "base64_encode" to mapOf("content" to "fixture"),
                "base64_decode" to mapOf("content" to "Zml4dHVyZQ=="),
                "random_string" to mapOf("length" to 4, "characterSet" to "ab"),
                "hash_compute" to mapOf("content" to "fixture", "algorithm" to "sha256"),
                "jwt_decode" to mapOf("token" to "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0."),
                "decode_as" to mapOf("base64" to "Zml4dHVyZQ==", "encoding" to "RAW"),
                "cookie_jar_get" to emptyMap(),
                "project_options_get" to emptyMap(),
                "user_options_get" to emptyMap(),
                "project_options_set" to mapOf("json" to "{}"),
                "user_options_set" to mapOf("json" to "{}"),
                "collaborator_generate" to emptyMap(),
                "collaborator_poll" to emptyMap(),
                "scanner_issues" to page,
                "scan_audit_start" to mapOf("builtInConfiguration" to "active"),
                "scan_audit_start_mode" to (target + mapOf("mode" to "active", "requests" to listOf(raw))),
                "scan_audit_start_requests" to (target + mapOf("builtInConfiguration" to "active", "requests" to listOf(raw))),
                "scan_crawl_start" to mapOf("seedUrls" to listOf("https://fixture.test/")),
                "scan_task_status" to mapOf("taskId" to taskId),
                "scan_report" to mapOf("allIssues" to true, "format" to "HTML", "path" to "nim17-fixture-report.html"),
                "scan_task_delete" to mapOf("taskId" to taskId),
                "proxy_http_history" to page,
                "proxy_http_history_regex" to (page + mapOf("regex" to ".*")),
                "proxy_history_annotate" to mapOf("regex" to ".*", "note" to "fixture"),
                "response_body_search" to (page + mapOf("regex" to ".*")),
                "proxy_ws_history" to page,
                "proxy_ws_history_regex" to (page + mapOf("regex" to ".*")),
                "site_map" to page,
                "site_map_regex" to (page + mapOf("regex" to ".*")),
                "scope_check" to mapOf("url" to "https://fixture.test/"),
                "scope_include" to mapOf("url" to "https://fixture.test/"),
                "scope_exclude" to mapOf("url" to "https://fixture.test/"),
                "task_engine_state" to mapOf("running" to true),
                "proxy_intercept" to mapOf("intercepting" to false),
                "editor_get" to emptyMap(),
                "editor_set" to mapOf("text" to raw),
                "issue_create" to mapOf("name" to "Fixture finding", "detail" to "Synthetic evidence", "baseUrl" to "https://fixture.test/", "severity" to "LOW", "confidence" to "FIRM"),
                "ai_analyze" to mapOf("text" to "Synthetic offline analysis"),
                "ai_passive_scan" to emptyMap(),
                "ai_findings_recent" to emptyMap(),
                "redact_preview" to mapOf("text" to "fixture", "mode" to "OFF"),
                "ai_audit_query" to emptyMap(),
                "ai_backends_list" to emptyMap(),
            )
        return result
    }
}
