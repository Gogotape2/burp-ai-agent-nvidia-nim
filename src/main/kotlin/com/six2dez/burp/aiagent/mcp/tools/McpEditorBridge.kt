package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.InvocationType
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import com.six2dez.burp.aiagent.mcp.McpToolContext
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/** An explicit Montoya editor binding survives focus moving to chat without selecting chat itself. */
object McpEditorBridge {
    private data class Binding(
        val editor: MessageEditorHttpRequestResponse,
        val editable: Boolean,
        val original: String,
    )

    private val binding = AtomicReference<Binding?>(null)
    private const val EDT_TIMEOUT_SECONDS = 5L

    fun bind(event: ContextMenuEvent) {
        event.messageEditorRequestResponse().ifPresent { editor ->
            val editable = event.isFrom(InvocationType.MESSAGE_EDITOR_REQUEST) || event.isFrom(InvocationType.MESSAGE_EDITOR_RESPONSE)
            onEdt { binding.set(Binding(editor, editable, contents(editor))) }
        }
    }

    fun clear() {
        binding.set(null)
    }

    fun read(context: McpToolContext): String {
        val snapshot =
            onEdt {
                val editor = selected().editor
                contents(editor) to editor.requestResponse().request().url()
            }
        McpScopeFilter.rejectIfOutOfScope(snapshot.second, context)?.let { throw IllegalArgumentException(it) }
        return snapshot.first
    }

    fun write(
        text: String,
        context: McpToolContext,
    ): String {
        val selected = selected()
        check(selected.editable) { "The selected message is read-only. Select an editable request/response in Burp and open its context menu." }
        val rr = onEdt { selected.editor.requestResponse() }
        McpScopeFilter.rejectIfOutOfScope(rr.request().url(), context)?.let { throw IllegalArgumentException(it) }
        val requestSide = onEdt { selected.editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST }
        // Factory work remains off the EDT; only editor access and assignment run there.
        val request = if (requestSide) McpTextMessages.request(rr.request().httpService(), text) else null
        val response = if (requestSide) null else McpTextMessages.response(text)
        request?.let { McpScopeFilter.rejectIfOutOfScope(it.url(), context)?.let { reason -> throw IllegalArgumentException(reason) } }
        return onEdt {
            check(binding.get() === selected && contents(selected.editor) == selected.original) { "The selected editor changed. Reopen its context menu before replacing it." }
            if (request != null) selected.editor.setRequest(request) else selected.editor.setResponse(checkNotNull(response))
            binding.set(selected.copy(original = text))
            "Editor text has been set"
        }
    }

    private fun selected(): Binding = checkNotNull(binding.get()) { "No message editor selected. Open the context menu on a Burp HTTP message first." }

    private fun contents(editor: MessageEditorHttpRequestResponse): String {
        val rr = editor.requestResponse()
        return if (editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
            rr.request().toString()
        } else {
            rr.response()?.toString() ?: error("The selected message has no response")
        }
    }

    private fun <T> onEdt(action: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return action()
        val task = FutureTask(action)
        SwingUtilities.invokeLater(task)
        return try {
            task.get(EDT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } finally {
            task.cancel(false)
        }
    }
}
