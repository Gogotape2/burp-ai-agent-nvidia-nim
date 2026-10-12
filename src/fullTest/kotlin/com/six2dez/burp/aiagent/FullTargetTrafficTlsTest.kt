package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Phase 29 (D-16) — the MCP half of [TargetTrafficTlsTest], moved here verbatim from it.
 *
 * `http1_request` and `http2_request` are generic tools, which only the full flavor packages. Their
 * behaviour pins — target traffic sent with no upstream TLS verification, and HTTP/2 mode kept — run
 * here on the full classpath. The fixture they use is copied from TargetTrafficTlsTest unchanged,
 * except that the teardown has no scanners to shut down. The send-site table and both whole-tree
 * ledgers stay in TargetTrafficTlsTest.
 */
class FullTargetTrafficTlsTest {
    private var savedFactory: MontoyaObjectFactory? = null
    private lateinit var factory: MontoyaObjectFactory
    private lateinit var options: RequestOptions

    @BeforeEach
    fun installFactory() {
        savedFactory = ObjectFactoryLocator.FACTORY
        options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        whenever(factory.requestOptions()).thenReturn(options)
        whenever(factory.httpRequestResponse(any<HttpRequest>(), any<HttpResponse>())).thenAnswer { invocation ->
            pairOf(invocation.getArgument(0), invocation.getArgument(1))
        }
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    @Test
    fun theMcpHttp1ToolSendsWithoutUpstreamTlsVerification() {
        val api = newDeepStubApi()
        val rawRequest = "GET / HTTP/1.1\r\nHost: $HOST\r\n\r\n"
        val args =
            "{\"content\":${jsonString(rawRequest)},\"targetHostname\":\"$HOST\"," +
                "\"targetPort\":443,\"usesHttps\":true}"

        val result = exec("http1_request", args, contextWith(api))

        assertEquals(1, sendsOn(api.http()), "expected exactly one send, tool output: $result")
        assertEquals(0, tlsOptionCalls(), "http1_request must not require upstream TLS verification on target traffic")
    }

    @Test
    fun theMcpHttp2ToolKeepsHttp2ModeWithoutUpstreamTlsVerification() {
        val api = newDeepStubApi()
        val args =
            "{\"pseudoHeaders\":{\"method\":\"GET\",\"path\":\"/\",\"scheme\":\"https\",\"authority\":\"$HOST\"}," +
                "\"headers\":{},\"requestBody\":\"\",\"targetHostname\":\"$HOST\"," +
                "\"targetPort\":443,\"usesHttps\":true}"

        val result = exec("http2_request", args, contextWith(api))

        assertEquals(1, sendsOn(api.http()), "expected exactly one send, tool output: $result")
        verify(options).withHttpMode(HttpMode.HTTP_2)
        assertEquals(0, tlsOptionCalls(), "http2_request must not require upstream TLS verification on target traffic")
    }

    private fun tlsOptionCalls(): Int = Mockito.mockingDetails(options).invocations.count { it.method.name == TLS_OPTION }

    private fun sendsOn(http: Http): Int = Mockito.mockingDetails(http).invocations.count { it.method.name == "sendRequest" }

    private fun pairOf(
        sent: HttpRequest?,
        answer: HttpResponse?,
    ): HttpRequestResponse =
        mock {
            on { request() } doReturn sent
            on { response() } doReturn answer
        }

    private fun exec(
        toolId: String,
        argsJson: String,
        context: McpToolContext,
    ): String = McpToolExecutor.executeTool(toolId, argsJson, context, ToolCallOrigin.UserSlashCommand)

    private fun contextWith(api: MontoyaApi): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "test",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = true,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = McpToolCatalog.unsafeToolIds(),
            limiter = McpRequestLimiter(8),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 16_384,
            scopeOnly = false,
        )

    private fun newDeepStubApi(): MontoyaApi {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.scope().isInScope(any())).thenReturn(true)
        return api
    }

    private fun jsonString(raw: String): String {
        val escaped =
            raw
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
        return "\"$escaped\""
    }

    private companion object {
        const val TLS_OPTION = "withUpstreamTLSVerification"
        const val HOST = "example.com"
    }
}
