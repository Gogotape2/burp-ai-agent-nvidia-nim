package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.registerTools
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import kotlin.math.min

class McpStdioBridge(
    private val api: MontoyaApi,
    private val contextFactory: McpRuntimeContextFactory = McpRuntimeContextFactory(api),
) {
    private var scope: CoroutineScope? = null
    private var job: Job? = null
    private var server: Server? = null
    private var transport: StdioServerTransport? = null

    fun setAiRequestLogger(logger: AiRequestLogger) {
        contextFactory.aiRequestLogger = logger
    }

    fun start(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings,
    ) {
        stop()
        val context = contextFactory.create(settings, privacyMode, determinismMode, preprocessSettings)

        val mcpServer =
            Server(
                serverInfo = Implementation("burp-ai-agent", "0.6.0"),
                options =
                    ServerOptions(
                        capabilities =
                            ServerCapabilities(
                                tools = ServerCapabilities.Tools(listChanged = false),
                            ),
                    ),
            )
        mcpServer.registerTools(api, context)

        val source = System.`in`.asSource().buffered()
        val sink = System.out.asSink().buffered()
        val stdioTransport = StdioServerTransport(source, sink)

        server = mcpServer
        transport = stdioTransport

        // Phase 33 / D-12: the extension-owned dispatcher that unload closes.
        val newScope = CoroutineScope(McpCoroutines.dispatcher() + SupervisorJob())
        scope = newScope
        job =
            newScope.launch {
                mcpServer.connect(stdioTransport)
                stdioTransport.start()
            }

        api.logging().logToOutput("MCP stdio bridge started.")
    }

    /**
     * Stops the bridge. With a [deadline] (unload, Phase 33 D-05) each close waits at most what is left of
     * it, and is skipped once nothing is left; without one each close keeps its own 5 s bound.
     */
    fun stop(deadline: ShutdownDeadline? = null) {
        job?.cancel()
        job = null
        val currentTransport = transport
        val currentServer = server
        val currentScope = scope
        transport = null
        server = null
        scope = null
        runBlocking {
            closeTimeoutMs(deadline).takeIf { it > 0 }?.let { budget -> withTimeoutOrNull(budget) { currentTransport?.close() } }
            closeTimeoutMs(deadline).takeIf { it > 0 }?.let { budget -> withTimeoutOrNull(budget) { currentServer?.close() } }
        }
        currentScope?.coroutineContext?.get(kotlinx.coroutines.Job)?.cancel()
    }

    companion object {
        private const val CLOSE_TIMEOUT_MS = 5_000L

        /** The bound for one close: [CLOSE_TIMEOUT_MS], capped by what is left of [deadline] when there is one. */
        internal fun closeTimeoutMs(deadline: ShutdownDeadline?): Long = min(CLOSE_TIMEOUT_MS, deadline?.remainingMs() ?: CLOSE_TIMEOUT_MS)
    }
}
