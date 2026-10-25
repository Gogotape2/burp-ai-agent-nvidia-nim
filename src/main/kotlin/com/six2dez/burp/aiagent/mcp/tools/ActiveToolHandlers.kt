package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.Json

internal object ActiveToolHandlers {
    val ids = setOf("intruder_attack_start", "intruder_attack_status", "intruder_attack_results", "intruder_attack_cancel", "websocket_open", "websocket_send", "websocket_receive", "websocket_close", "websocket_connections")
    private val json = Json { ignoreUnknownKeys = true }

    fun execute(
        name: String,
        raw: String?,
        context: McpToolContext,
    ): String {
        val runtime = checkNotNull(context.activeRuntime) { "Active testing runtime is not initialized" }
        val arguments = raw ?: "{}"
        val checkUrl: (String) -> Unit = { url -> requireScope(url, context) }
        val checkAttack: (IntruderAttackStart, String) -> Unit = { input, content -> requireScope(scopeUrl(input, content), context) }
        val result =
            when (name) {
                "intruder_attack_start" -> {
                    val input = json.decodeFromString<IntruderAttackStart>(arguments)
                    val resolved = input.copy(targetHostname = context.resolveHost(input.targetHostname), concurrency = if (context.determinismMode) 1 else input.concurrency)
                    runtime.attacks.start(resolved) { checkAttack(resolved, it) }
                }
                "intruder_attack_status" -> runtime.attacks.status(json.decodeFromString<IntruderAttackId>(arguments).attackId, checkAttack)
                "intruder_attack_results" -> runtime.attacks.results(json.decodeFromString<IntruderAttackResults>(arguments), checkAttack)
                "intruder_attack_cancel" -> runtime.attacks.cancel(json.decodeFromString<IntruderAttackId>(arguments).attackId) { _, _ -> }
                "websocket_open" -> open(arguments, context, runtime)
                "websocket_send" -> runtime.websockets.send(json.decodeFromString<WebSocketSend>(arguments), checkUrl)
                "websocket_receive" -> runtime.websockets.receive(json.decodeFromString<WebSocketReceive>(arguments), context.privacyMode == PrivacyMode.OFF, checkUrl)
                "websocket_close" -> runtime.websockets.disconnect(json.decodeFromString<WebSocketId>(arguments).connectionId) { }
                "websocket_connections" -> runtime.websockets.connections { McpScopeFilter.rejectIfOutOfScope(it, context) == null }
                else -> error("Unknown active testing tool")
            }
        return redactActiveToolResult(result, context).toString()
    }

    private fun open(
        arguments: String,
        context: McpToolContext,
        runtime: McpActiveRuntime,
    ): kotlinx.serialization.json.JsonObject {
        val input = json.decodeFromString<WebSocketOpen>(arguments).let { it.copy(targetHostname = context.resolveHost(it.targetHostname)) }
        validateService(input)
        require(input.path.startsWith('/') && !input.path.contains('\r') && !input.path.contains('\n')) { "WebSocket path must start with / and contain no line breaks" }
        require(input.content == null || input.content.toByteArray().size <= ActiveToolLimits.MAX_TEMPLATE_BYTES) { "Upgrade request exceeds 1 MiB" }
        val rawRequest = input.content ?: "GET ${input.path} HTTP/1.1\r\n"
        require(rawRequest.startsWith("GET ")) { "WebSocket upgrade must use GET" }
        val url = scopeUrl(input, rawRequest)
        requireScope(url, context)
        return runtime.websockets.open(input, url)
    }

    private fun scopeUrl(
        service: HttpServiceParams,
        content: String,
    ): String = McpScopeFilter.deriveScopeUrl(service.targetHostname, service.targetPort, service.usesHttps, content)

    private fun requireScope(
        url: String,
        context: McpToolContext,
    ) {
        McpScopeFilter.rejectIfOutOfScope(url, context)?.let { error(it) }
    }

    fun schema(name: String): Tool.Input =
        when (name) {
            "intruder_attack_start" -> IntruderAttackStart::class.asInputSchema()
            "intruder_attack_status", "intruder_attack_cancel" -> IntruderAttackId::class.asInputSchema()
            "intruder_attack_results" -> IntruderAttackResults::class.asInputSchema()
            "websocket_open" -> WebSocketOpen::class.asInputSchema()
            "websocket_send" -> WebSocketSend::class.asInputSchema()
            "websocket_receive" -> WebSocketReceive::class.asInputSchema()
            "websocket_close" -> WebSocketId::class.asInputSchema()
            "websocket_connections" -> Tool.Input()
            else -> error("Unknown active tool schema")
        }
}
