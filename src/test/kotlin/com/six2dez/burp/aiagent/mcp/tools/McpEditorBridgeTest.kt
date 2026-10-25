package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.AfterEach
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
import java.util.Optional
import javax.swing.SwingUtilities

class McpEditorBridgeTest {
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val editor = mock<MessageEditorHttpRequestResponse>()
    private val rr = mock<HttpRequestResponse>()
    private val request = mock<HttpRequest>()

    @AfterEach
    fun clear() {
        McpEditorBridge.clear()
    }

    @Test
    fun readingAnOutOfScopeEditorDoesNotReturnItsContents() {
        bind(editable = true)
        val result = McpToolExecutor.executeToolResult("editor_get", "{}", context().copy(scopeOnly = true))
        assertTrue(result.isError == true)
        assertFalse((result.content.single() as TextContent).text.orEmpty().contains("private editor contents"))
    }

    @Test
    fun readOnlyViewerCannotBeWritten() {
        bind(editable = false)
        assertTrue(McpToolExecutor.executeToolResult("editor_set", """{"text":"new text"}""", context()).isError == true)
        verify(editor, never()).setRequest(any())
    }

    @Test
    fun manualEditsAfterBindingCannotBeOverwrittenByALateTool() {
        bind(editable = true)
        whenever(request.toString()).thenReturn("manual change")
        val buffer = mock<burp.api.montoya.core.ByteArray>()
        mockStatic(burp.api.montoya.core.ByteArray::class.java) { buffer }.use {
            mockStatic(HttpRequest::class.java).use { factory ->
                factory.`when`<HttpRequest> { HttpRequest.httpRequest(rr.request().httpService(), buffer) }.thenReturn(request)
                val result = McpToolExecutor.executeToolResult("editor_set", """{"text":"new text"}""", context())
                assertTrue(result.isError == true)
                assertTrue((result.content.single() as TextContent).text.orEmpty().contains("selected editor changed"), result.content.toString())
            }
        }
        verify(editor, never()).setRequest(any())
    }

    private fun bind(editable: Boolean) {
        whenever(request.httpService()).thenReturn(mock<burp.api.montoya.http.HttpService>())
        whenever(request.url()).thenReturn("https://fixture.test/")
        whenever(request.toString()).thenReturn("private editor contents")
        whenever(rr.request()).thenReturn(request)
        whenever(editor.requestResponse()).thenAnswer {
            assertTrue(SwingUtilities.isEventDispatchThread())
            rr
        }
        whenever(editor.selectionContext()).thenReturn(MessageEditorHttpRequestResponse.SelectionContext.REQUEST)
        val event = mock<ContextMenuEvent>()
        whenever(event.messageEditorRequestResponse()).thenReturn(Optional.of(editor))
        whenever(event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST)).thenReturn(editable)
        SwingUtilities.invokeAndWait { McpEditorBridge.bind(event) }
    }

    private fun context() = McpToolContext(api, PrivacyMode.OFF, false, "fixture", McpToolCatalog.all().associate { it.id to true }, true, McpToolCatalog.unsafeToolIds(), emptySet(), McpRequestLimiter(2), BurpSuiteEdition.PROFESSIONAL, 32768)
}
