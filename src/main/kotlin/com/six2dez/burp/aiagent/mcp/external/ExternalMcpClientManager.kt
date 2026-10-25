package com.six2dez.burp.aiagent.mcp.external

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.util.SsrfGuard
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.sse.SSE
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.Implementation
import io.modelcontextprotocol.kotlin.sdk.ListToolsRequest
import io.modelcontextprotocol.kotlin.sdk.TextContent
import io.modelcontextprotocol.kotlin.sdk.Tool
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport
import io.modelcontextprotocol.kotlin.sdk.client.StdioClientTransport
import io.modelcontextprotocol.kotlin.sdk.shared.Transport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.math.min
import kotlin.math.pow

// Trust-boundary constants (SC2) — every external tool result is wrapped before entering AI context.
private const val TRUST_BOUNDARY_OPEN = "[EXTERNAL-TOOL-RESULT:"
private const val TRUST_BOUNDARY_CLOSE = "[/EXTERNAL-TOOL-RESULT]"

// Reconnect policy constants (mirrored from McpSupervisor pattern).
private const val MAX_RECONNECT_ATTEMPTS = 3
private const val RECONNECT_DELAY_BASE_MS = 1000L
private const val RECONNECT_DELAY_MAX_MS = 30_000L
private const val SHUTDOWN_TIMEOUT_MS = 5000L
private const val CONNECT_TIMEOUT_MS = 30_000L
private const val CALL_TIMEOUT_MS = 120_000L
private const val MAX_TOOL_PAGES = 32
private const val MAX_EXTERNAL_TOOLS = 256
private const val STDERR_BUFFER_BYTES = 4096
private const val MILLIS_PER_SECOND = 1000
private const val MAX_RESULT_CHARS = 1_000_000

/**
 * Describes a single tool exposed by an external MCP server.
 *
 * The [name] field uses the fully-qualified `ext:<serverName>:<originalName>` form required by
 * the D-04 disambiguation contract. Callers must strip the `ext:<serverName>:` prefix before
 * forwarding the call to the remote server via [ExternalMcpClientManager.callTool].
 */
data class ExternalToolDescriptor(
    val serverName: String,
    val name: String,
    val description: String,
    val inputSchema: Tool.Input = Tool.Input(),
)

/**
 * Lifecycle state for a single external MCP server connection.
 * Mirrors [com.six2dez.burp.aiagent.mcp.McpServerState].
 */
sealed class ExternalMcpConnectionState {
    data object Disconnected : ExternalMcpConnectionState()

    data object Connecting : ExternalMcpConnectionState()

    data class Connected(
        val toolCount: Int,
    ) : ExternalMcpConnectionState()

    data class Retrying(
        val attempt: Int,
        val maxAttempts: Int,
    ) : ExternalMcpConnectionState()

    data class Error(
        val message: String,
    ) : ExternalMcpConnectionState()
}

/**
 * Internal holder for per-server connection state.
 */
private data class ServerConnection(
    val config: ExternalMcpServerConfig,
    @Volatile var client: Client? = null,
    @Volatile var transport: Transport? = null,
    @Volatile var process: Process? = null,
    val scope: CoroutineScope,
    var job: Job? = null,
    val stateRef: AtomicReference<ExternalMcpConnectionState> =
        AtomicReference(ExternalMcpConnectionState.Disconnected),
    val cachedTools: CopyOnWriteArrayList<ExternalToolDescriptor> = CopyOnWriteArrayList(),
    var retryCount: Int = 0,
)

/**
 * Manages the lifecycle of all configured external MCP server connections.
 *
 * Responsibilities:
 * - SSE connections via [SseClientTransport] with a dedicated [HttpClient] (CIO engine).
 * - stdio connections via [StdioClientTransport] using [ProcessBuilder] with a List argument
 *   (no shell expansion — T-16-03-CMD mitigation).
 * - Prefixes all external tool names with `ext:<serverName>:<tool>` (D-04).
 * - Wraps every [callTool] result in the trust-boundary marker (SC2 — T-16-03-PI mitigation).
 * - Audit-logs every tool invocation behind the [auditLogger] enabled gate (CR-02 allocation
 *   guard: allocations inside the if-block only when audit is active).
 * - Reconnect with exponential backoff up to [MAX_RECONNECT_ATTEMPTS] (via
 *   [ScheduledExecutorService] — mirrors [com.six2dez.burp.aiagent.mcp.McpSupervisor]).
 * - Bounded shutdown with [SHUTDOWN_TIMEOUT_MS] and [Process.destroyForcibly] for stdio
 *   (T-16-03-ZOM mitigation).
 *
 * Crypto contract: [ExternalMcpServerConfig.bearerToken] is ALWAYS plaintext on arrival — it
 * was decrypted by [com.six2dez.burp.aiagent.config.AgentSettingsRepository.loadExternalMcpServers].
 * This class MUST NOT call SecretCipher.decrypt.
 *
 * @param auditLogger optional [AuditLogger] instance for guarding allocation (CR-02).
 * @param clientFactory override for tests to inject a mock [Client].
 * @param scheduler optional [ScheduledExecutorService] for reconnect — overridden in tests.
 */
class ExternalMcpClientManager(
    private val auditLogger: AuditLogger? = null,
    private val clientFactory: (Implementation, ClientOptions) -> Client = { impl, opts -> Client(impl, opts) },
    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "burp-ai-external-mcp-reconnect").apply { isDaemon = true }
        },
    /**
     * Factory for spawning stdio subprocess — overridden in tests to inject a mock [Process].
     * Default implementation uses [ProcessBuilder] with a List (no shell expansion).
     */
    private val processFactory: (command: List<String>, envVars: Map<String, String>) -> Process = { cmd, env ->
        val pb = ProcessBuilder(cmd)
        // stdout is JSON-RPC; merging diagnostics into it corrupts the transport.
        pb.redirectErrorStream(false)
        pb.redirectInput(ProcessBuilder.Redirect.PIPE)
        pb.redirectOutput(ProcessBuilder.Redirect.PIPE)
        // CR-01: ProcessBuilder seeds environment() with a copy of Burp's parent environment.
        // Clear it so secrets in Burp's env (e.g. ANTHROPIC_API_KEY) are NEVER forwarded to the
        // stdio subprocess; inject ONLY the user-configured vars below (honors the no-inherit contract).
        pb.environment().clear()
        env.forEach { (k, v) -> pb.environment()[k] = v }
        pb.start()
    },
) {
    // Shared scope with SupervisorJob: one child-job failure does not cancel siblings.
    private val managerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Dedicated HttpClient for SSE transport — NEVER reuse the Ktor Netty server instance.
    private val httpClient =
        HttpClient(CIO) {
            install(SSE)
        }

    // All active server connections, thread-safe.
    private val connections = CopyOnWriteArrayList<ServerConnection>()
    private val stopped = AtomicBoolean(false)

    /**
     * Starts connections to all enabled servers in [configs].
     * Each server gets an independent child coroutine on [managerScope].
     */
    fun start(configs: List<ExternalMcpServerConfig>) {
        if (stopped.get()) return
        configs.filter { it.enabled }.forEach { config ->
            if (connections.any { it.config.name == config.name }) return@forEach
            val connection =
                ServerConnection(
                    config = config,
                    scope = managerScope,
                )
            connections.add(connection)
            connection.job =
                managerScope.launch {
                    connectServer(connection)
                }
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun connectServer(connection: ServerConnection) {
        val config = connection.config
        val serverName = config.name

        connection.stateRef.set(ExternalMcpConnectionState.Connecting)

        try {
            require(validExternalServerName(serverName)) { "Server name must use 1-64 printable characters without colons or brackets" }
            withTimeout(CONNECT_TIMEOUT_MS) {
                val transport = createExternalTransport(connection, httpClient, processFactory)

                val client =
                    clientFactory(
                        Implementation("burp-ai-agent-ext", com.six2dez.burp.aiagent.BuildFlags.VERSION),
                        ClientOptions(),
                    )
                connection.client = client

                client.connect(transport)

                val descriptors = discoverExternalTools(client, serverName)

                connection.cachedTools.clear()
                connection.cachedTools.addAll(descriptors)
                connection.retryCount = 0
                connection.stateRef.set(ExternalMcpConnectionState.Connected(descriptors.size))
            }
        } catch (e: TimeoutCancellationException) {
            cleanup(connection)
            scheduleReconnect(connection, e)
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Re-throw CancellationException — coroutine was cancelled intentionally (e.g. stop()).
            // Do NOT schedule reconnect on cancellation.
            throw e
        } catch (e: Exception) {
            cleanup(connection)
            scheduleReconnect(connection, e)
        } finally {
            if (stopped.get()) kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { cleanup(connection) }
        }
    }

    private fun scheduleReconnect(
        connection: ServerConnection,
        cause: Exception,
    ) {
        if (stopped.get()) return
        val attempt = ++connection.retryCount
        if (attempt > MAX_RECONNECT_ATTEMPTS) {
            val msg = "Connection failed after $MAX_RECONNECT_ATTEMPTS retries (${cause.javaClass.simpleName})"
            connection.stateRef.set(ExternalMcpConnectionState.Error(msg))
            return
        }

        val delayMs =
            min(
                (RECONNECT_DELAY_BASE_MS * (2.0.pow(attempt - 1))).toLong(),
                RECONNECT_DELAY_MAX_MS,
            )
        connection.stateRef.set(
            ExternalMcpConnectionState.Retrying(attempt, MAX_RECONNECT_ATTEMPTS),
        )

        scheduler.schedule(
            {
                if (connection.config.enabled && !stopped.get()) {
                    connection.job =
                        managerScope.launch {
                            connectServer(connection)
                        }
                }
            },
            delayMs,
            TimeUnit.MILLISECONDS,
        )
    }

    /**
     * Returns all tool descriptors across all connected servers. Thread-safe.
     */
    fun availableTools(): List<ExternalToolDescriptor> = connections.filter { it.stateRef.get() is ExternalMcpConnectionState.Connected }.flatMap { it.cachedTools.toList() }

    /**
     * Calls a tool on the named external server.
     *
     * The [toolName] parameter must be the RAW tool name as declared by the remote server (i.e.
     * the `ext:<serverName>:` prefix must already be stripped by the caller before passing here).
     *
     * Every result is wrapped with the trust-boundary marker (SC2 / T-16-03-PI).
     * Every invocation is audit-logged when audit is enabled (CR-02 allocation guard).
     * The bearer token is NEVER included in audit output (T-16-03-TL).
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun callTool(
        serverName: String,
        toolName: String,
        args: Map<String, Any?>,
    ): String = callToolResult(serverName, toolName, args).content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }

    // Remote transports may throw SDK-specific failures; expose sanitized status only.
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun callToolResult(
        serverName: String,
        toolName: String,
        args: Map<String, Any?>,
    ): CallToolResult {
        fun result(
            text: String,
            error: Boolean,
        ) = CallToolResult(content = listOf(TextContent(wrapWithTrustBoundary(serverName, text))), isError = error)
        val connection =
            connections.firstOrNull { it.config.name == serverName }
                ?: return result("Error: server '$serverName' not found", true)

        if (connection.stateRef.get() !is ExternalMcpConnectionState.Connected) return result("Error: server is not connected", true)
        if (connection.cachedTools.none { it.name == "ext:$serverName:$toolName" }) return result("Error: unknown external tool", true)

        val client =
            connection.client
                ?: return result("Error: server '$serverName' not connected", true)

        return try {
            val callResult = withTimeout(CALL_TIMEOUT_MS) { checkNotNull(client.callTool(toolName, args, false, null)) { "Empty MCP response" } }
            val (finalText, failed) = externalResultText(callResult)

            // CR-02 allocation guard: only allocate buildMap when audit is active.
            if (auditLogger?.isEnabled() == true) {
                AuditLogger.emitGlobal(
                    "external_mcp_call",
                    buildMap {
                        put("server", serverName)
                        put("tool", toolName)
                        put("status", if (failed) "error" else "ok")
                    },
                )
            }

            result(finalText, failed)
        } catch (e: TimeoutCancellationException) {
            result("Error: external tool timed out after ${CALL_TIMEOUT_MS / MILLIS_PER_SECOND} seconds (${e.javaClass.simpleName})", true)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // CR-02 allocation guard on error path too.
            if (auditLogger?.isEnabled() == true) {
                AuditLogger.emitGlobal(
                    "external_mcp_call",
                    buildMap {
                        put("server", serverName)
                        put("tool", toolName)
                        put("status", "error")
                        put("error", e.javaClass.simpleName)
                        // Note: bearer token is never included in audit output (T-16-03-TL).
                    },
                )
            }
            val failure = ExternalMcpConnectionState.Error("Transport failed (${e.javaClass.simpleName})")
            if (connection.stateRef.getAndSet(failure) is ExternalMcpConnectionState.Connected) {
                managerScope.launch {
                    cleanup(connection)
                    scheduleReconnect(connection, e)
                }
            }
            result("Error calling external tool (${e.javaClass.simpleName})", true)
        }
    }

    /**
     * Wraps [rawResult] in the trust-boundary marker for prompt-injection defense (SC2).
     *
     * Format: `[EXTERNAL-TOOL-RESULT:<serverName>]\n<rawResult>\n[/EXTERNAL-TOOL-RESULT]`
     */
    @Suppress("MemberVisibilityCanBePrivate")
    internal fun wrapWithTrustBoundary(
        serverName: String,
        rawResult: String,
    ): String {
        // WR-01: neutralize any close-marker the (untrusted) server embedded in its result, so it
        // cannot terminate the boundary early and smuggle content out as trusted text.
        val safeResult = rawResult.replace(TRUST_BOUNDARY_CLOSE, "[/EXTERNAL-TOOL-RESULT-ESCAPED]")
        return "$TRUST_BOUNDARY_OPEN$serverName]\n$safeResult\n$TRUST_BOUNDARY_CLOSE"
    }

    /**
     * Returns the current connection state for [serverName], or [ExternalMcpConnectionState.Disconnected]
     * if the server is not registered.
     */
    fun connectionState(serverName: String): ExternalMcpConnectionState =
        connections
            .firstOrNull { it.config.name == serverName }
            ?.stateRef
            ?.get()
            ?: ExternalMcpConnectionState.Disconnected

    /**
     * Stops all connections and the manager scope.
     *
     * For each server:
     * 1. Cancel the coroutine job.
     * 2. Close transport and client with [SHUTDOWN_TIMEOUT_MS] bounded timeout.
     * 3. [Process.destroyForcibly] for stdio servers after close (T-16-03-ZOM mitigation).
     *
     * Mirrors [com.six2dez.burp.aiagent.mcp.McpStdioBridge.stop] pattern.
     */
    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        scheduler.shutdownNow()
        connections.forEach { connection ->
            connection.job?.cancel()
            connection.job = null

            runBlocking { cleanup(connection) }

            connection.stateRef.set(ExternalMcpConnectionState.Disconnected)
            connection.cachedTools.clear()
        }

        connections.clear()
        managerScope.coroutineContext[kotlinx.coroutines.Job]?.cancel()

        scheduler.shutdown()
        try {
            scheduler.awaitTermination(SHUTDOWN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        runBlocking {
            withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) { httpClient.close() }
        }
    }

    private suspend fun cleanup(connection: ServerConnection) {
        val resources =
            synchronized(connection) {
                Triple(connection.client, connection.transport, connection.process).also {
                    connection.client = null
                    connection.transport = null
                    connection.process = null
                    connection.cachedTools.clear()
                }
            }
        withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) { runCatching { resources.first?.close() } }
        withTimeoutOrNull(SHUTDOWN_TIMEOUT_MS) { runCatching { resources.second?.close() } }
        resources.third?.destroyForcibly()
    }
}

private fun createExternalTransport(
    connection: ServerConnection,
    httpClient: HttpClient,
    processFactory: (List<String>, Map<String, String>) -> Process,
): Transport {
    val config = connection.config
    val serverName = config.name
    val transport: Transport
    when (config.transport) {
        ExternalMcpTransport.SSE -> {
            val uri = java.net.URI(config.url)
            require(uri.scheme in setOf("http", "https") && uri.host != null && uri.userInfo == null) { "Invalid MCP SSE URL" }
            require(config.bearerToken.none { it == '\r' || it == '\n' }) { "Invalid MCP bearer token" }
            // SSRF advisory check — soft warning only (non-blocking per SC3 / D-01).
            if (SsrfGuard.isPrivateOrLinkLocal(config.url)) {
                System.err.println("[ExternalMcpClientManager] WARNING [$serverName]: private/internal SSE URL")
            }
            // Use config.bearerToken DIRECTLY — it is already plaintext (Plan 16-02 contract).
            // DO NOT call cipher.decrypt here.
            transport =
                SseClientTransport(
                    client = httpClient,
                    urlString = config.url,
                    requestBuilder = {
                        if (config.bearerToken.isNotBlank()) {
                            headers.append("Authorization", "Bearer ${config.bearerToken}")
                        }
                    },
                )
            connection.transport = transport
        }
        ExternalMcpTransport.STDIO -> {
            // Security: processFactory uses ProcessBuilder(List) — prevents shell expansion (T-16-03-CMD).
            // Do NOT call Runtime.exec(String) or ProcessBuilder(String) directly.
            val command = config.command + config.extraArgs
            // Inject only user-configured env vars — do NOT inherit Burp's environment
            // (prevents secret leakage via ANTHROPIC_API_KEY etc.).
            val process = processFactory(command, config.envVars)
            connection.process = process
            process.errorStream?.let { stderr ->
                Thread({
                    runCatching {
                        stderr.use { stream ->
                            val buffer = ByteArray(STDERR_BUFFER_BYTES)
                            while (stream.read(buffer) >= 0) { /* Drain diagnostics without retaining secrets. */ }
                        }
                    }
                }, "burp-ai-external-mcp-stderr").apply {
                    isDaemon = true
                    start()
                }
            }

            transport =
                StdioClientTransport(
                    input = process.inputStream.asSource().buffered(),
                    output = process.outputStream.asSink().buffered(),
                )
            connection.transport = transport
        }
    }
    return transport
}

private suspend fun discoverExternalTools(
    client: Client,
    serverName: String,
): List<ExternalToolDescriptor> {
    val descriptors = mutableListOf<ExternalToolDescriptor>()
    val cursors = mutableSetOf<String>()
    var cursor: String? = null
    var pages = 0
    do {
        check(++pages <= MAX_TOOL_PAGES) { "External tool discovery page limit exceeded" }
        val toolsResult = checkNotNull(client.listTools(ListToolsRequest(cursor = cursor), null)) { "No tool discovery response" }
        descriptors.addAll(
            toolsResult.tools.map { tool ->
                ExternalToolDescriptor(
                    serverName = serverName,
                    name = "ext:$serverName:${tool.name}",
                    description = tool.description.orEmpty(),
                    inputSchema = tool.inputSchema,
                )
            },
        )
        check(descriptors.size <= MAX_EXTERNAL_TOOLS) { "External tool discovery count limit exceeded" }
        cursor = toolsResult.nextCursor
        check(cursor == null || cursors.add(cursor!!)) { "Repeated external tool discovery cursor" }
    } while (cursor != null)
    check(descriptors.map { it.name }.distinct().size == descriptors.size) { "Duplicate external tool names" }
    return descriptors
}

private fun externalResultText(result: io.modelcontextprotocol.kotlin.sdk.CallToolResultBase): Pair<String, Boolean> {
    val raw = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
    val unsupported = result.content.any { it !is TextContent }
    val failed = result.isError == true || (unsupported && raw.isBlank())
    val bounded = raw.take(MAX_RESULT_CHARS) + if (raw.length > MAX_RESULT_CHARS) "\n[External result truncated]" else ""
    val text = bounded.ifBlank { if (unsupported) "Error: external tool returned unsupported non-text content" else "Tool completed with no text content." }
    return text to failed
}
