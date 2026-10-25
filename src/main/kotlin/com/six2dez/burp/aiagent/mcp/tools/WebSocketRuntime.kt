package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.websocket.BinaryMessage
import burp.api.montoya.websocket.TextMessage
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler
import com.six2dez.burp.aiagent.util.scheduleGuarded
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Only extension-owned sockets are addressable. Captured browser sockets remain read-only history. */
internal class WebSocketRuntime(
    private val api: MontoyaApi,
    private val create: (WebSocketOpen) -> burp.api.montoya.websocket.extension.ExtensionWebSocketCreation = { input ->
        val service = input.toMontoyaService()
        if (input.content == null) api.websockets().createWebSocket(service, input.path) else api.websockets().createWebSocket(McpTextMessages.request(service, normalizeHttpRequest(input.content)))
    },
) : AutoCloseable {
    private val sockets = ConcurrentHashMap<String, Connection>()
    private val slots = Semaphore(ActiveToolLimits.MAX_CONNECTIONS)
    private val closed = AtomicBoolean()
    private val operations = WebSocketOperations()
    private val reaper = Executors.newSingleThreadScheduledExecutor { task -> Thread(task, "ai-websocket-expiry").apply { isDaemon = true } }

    init {
        reaper.scheduleGuarded("WebSocketRuntime", "expire", { api.logging().logToError(it) }, ActiveToolLimits.REAPER_SECONDS, ActiveToolLimits.REAPER_SECONDS, TimeUnit.SECONDS) { expire() }
    }

    // Resource ownership must be unwound for arbitrary exceptions from the vendor transport.
    @Suppress("TooGenericExceptionCaught")
    fun open(
        input: WebSocketOpen,
        url: String,
    ): JsonObject {
        validateService(input)
        validateTimeout(input.timeoutMs)
        check(!closed.get()) { "WebSocket runtime is closed" }
        prune()
        check(slots.tryAcquire()) { "At most eight extension WebSocket connections may be open" }
        val released = AtomicBoolean()
        val release = { if (released.compareAndSet(false, true)) slots.release() }
        val connection =
            operations.run(input.timeoutMs, onSkipped = release, disposeLate = { it.disconnect() }) {
                try {
                    check(!closed.get()) { "WebSocket runtime is closed" }
                    val creation = create(input)
                    val socket = creation.webSocket().orElse(null)
                    if (creation.status() != ExtensionWebSocketCreationStatus.SUCCESS || socket == null) {
                        socket?.close()
                        error("WebSocket handshake failed: ${creation.status()}; HTTP ${creation.upgradeResponse().orElse(null)?.statusCode() ?: 0}")
                    }
                    val result = Connection("ws_${UUID.randomUUID()}", url, socket, release)
                    try {
                        result.registration = socket.registerMessageHandler(result)
                        check(!closed.get()) { "WebSocket runtime closed during connection" }
                        result
                    } catch (e: Exception) {
                        result.disconnect()
                        throw e
                    }
                } catch (e: Exception) {
                    release()
                    throw e
                }
            }
        synchronized(sockets) {
            if (closed.get() || sockets.size >= ActiveToolLimits.MAX_RETAINED_CONNECTIONS) {
                connection.disconnect()
                error("WebSocket runtime closed or connection registry full")
            }
            sockets[connection.id] = connection
        }
        return connection.summary()
    }

    fun send(
        input: WebSocketSend,
        checkScope: (String) -> Unit,
    ): JsonObject {
        validateTimeout(input.timeoutMs)
        require((input.text == null) != (input.base64 == null)) { "Supply exactly one of text or base64" }
        val text = input.text
        val binary =
            input.base64?.let {
                require(it.length <= ActiveToolLimits.MAX_FRAME_BYTES * 2) { "Binary message exceeds 64 KiB" }
                Base64.getDecoder().decode(it).also { bytes -> require(bytes.size <= ActiveToolLimits.MAX_FRAME_BYTES) { "Binary message exceeds 64 KiB" } }
            }
        require(text == null || text.toByteArray().size <= ActiveToolLimits.MAX_FRAME_BYTES) { "Text message exceeds 64 KiB" }
        val connection = find(input.connectionId, checkScope)
        return operations.run(input.timeoutMs) {
            check(!closed.get()) { "WebSocket runtime is closed" }
            checkScope(connection.url)
            check(!connection.isClosed.get()) { "WebSocket connection is closed" }
            if (text != null) connection.socket.sendTextMessage(WebSocketTextCodec.encode(text)) else connection.socket.sendBinaryMessage(McpTextMessages.binary(checkNotNull(binary)))
            connection.record("OUTBOUND", text, binary, binary?.size ?: text.orEmpty().toByteArray().size)
            connection.summary()
        }
    }

    fun receive(
        input: WebSocketReceive,
        includeBinary: Boolean,
        checkScope: (String) -> Unit,
    ): JsonObject {
        require(input.afterSequence >= 0 && input.count in 1..ActiveToolLimits.MAX_PAGE && input.waitMs in 0..ActiveToolLimits.MAX_WAIT_MS) { "afterSequence must be non-negative; count 1-100; waitMs 0-30000" }
        return find(input.connectionId, checkScope).receive(input, includeBinary)
    }

    fun disconnect(
        id: String,
        checkScope: (String) -> Unit,
    ): JsonObject {
        val connection = find(id, checkScope)
        return operations.run(ActiveToolLimits.DEFAULT_WS_TIMEOUT_MS) {
            connection.disconnect()
            connection.summary()
        }
    }

    fun connections(inScope: (String) -> Boolean): JsonArray =
        JsonArray(
            sockets.values
                .filter { inScope(it.url) }
                .sortedBy { it.created }
                .map { it.summary() },
        )

    private fun find(
        id: String,
        checkScope: (String) -> Unit,
    ): Connection = checkNotNull(sockets[id]) { "Unknown or expired connectionId" }.also { checkScope(it.url) }

    private fun validateTimeout(value: Long) {
        require(value in ActiveToolLimits.MIN_TIMEOUT_MS..ActiveToolLimits.MAX_TIMEOUT_MS) { "timeoutMs must be 1000-120000" }
    }

    private fun prune() {
        sockets.values.filter { it.isClosed.get() && System.currentTimeMillis() - it.lastUsed > ActiveToolLimits.RETENTION_MS }.forEach { sockets.remove(it.id, it) }
        if (sockets.size >= ActiveToolLimits.MAX_RETAINED_CONNECTIONS) {
            sockets.values
                .filter { it.isClosed.get() }
                .minByOrNull { it.created }
                ?.let { sockets.remove(it.id, it) }
        }
    }

    private fun expire() {
        sockets.values.filter { !it.isClosed.get() && System.currentTimeMillis() - it.lastUsed > ActiveToolLimits.IDLE_TIMEOUT_MS }.forEach { connection ->
            runCatching { operations.execute { runCatching { connection.disconnect() } } }
        }
        prune()
    }

    override fun close() {
        val owned =
            synchronized(sockets) {
                closed.set(true)
                sockets.values.toList().also { sockets.clear() }
            }
        reaper.shutdownNow()
        owned.forEach { connection -> runCatching { operations.execute { runCatching { connection.disconnect() } } } }
        // Already-running opens dispose their late results after noticing closed=true.
        operations.close()
    }

    private class Connection(
        val id: String,
        val url: String,
        val socket: ExtensionWebSocket,
        val release: () -> Unit,
    ) : ExtensionWebSocketMessageHandler {
        val created = System.currentTimeMillis()

        @Volatile var lastUsed = created

        @Volatile var registration: Registration? = null
        val isClosed = AtomicBoolean()
        private val lock = ReentrantLock()
        private val changed = lock.newCondition()
        private val frames = ArrayDeque<Frame>()
        private var sequence = 0L
        private var bytes = 0
        private var dropped = 0L

        override fun textMessageReceived(textMessage: TextMessage) {
            val (text, originalBytes) = WebSocketTextCodec.capture(textMessage.payload())
            record("INBOUND", text, null, originalBytes)
        }

        override fun binaryMessageReceived(binaryMessage: BinaryMessage) {
            val data = binaryMessage.payload()
            val capture = data.subArray(0, minOf(data.length(), ActiveToolLimits.MAX_FRAME_BYTES)).bytes
            record("INBOUND", null, capture, data.length())
        }

        override fun onClose() {
            markClosed()
        }

        private fun markClosed() {
            if (isClosed.compareAndSet(false, true)) {
                release()
                lock.withLock { changed.signalAll() }
            }
        }

        fun disconnect() {
            if (isClosed.compareAndSet(false, true)) {
                release()
                lock.withLock { changed.signalAll() }
                try {
                    socket.close()
                } finally {
                    registration?.deregister()
                }
            }
        }

        fun record(
            direction: String,
            text: String?,
            binary: kotlin.ByteArray?,
            originalBytes: Int,
        ) = lock.withLock {
            if (isClosed.get()) return@withLock
            if (direction == "OUTBOUND") lastUsed = System.currentTimeMillis()
            val frame = Frame(++sequence, direction, text, binary, originalBytes)
            frames.addLast(frame)
            bytes += frame.size
            while (frames.size > ActiveToolLimits.MAX_FRAMES || bytes > ActiveToolLimits.MAX_BUFFER_BYTES) {
                bytes -= frames.removeFirst().size
                dropped++
            }
            changed.signalAll()
        }

        fun summary(): JsonObject =
            lock.withLock {
                buildJsonObject {
                    put("connectionId", id)
                    put("url", url)
                    put("state", if (isClosed.get()) "CLOSED" else "OPEN")
                    put("lastSequence", sequence)
                    put("bufferedMessages", frames.size)
                    put("droppedMessages", dropped)
                }
            }

        fun receive(
            input: WebSocketReceive,
            includeBinary: Boolean,
        ): JsonObject =
            lock.withLock {
                lastUsed = System.currentTimeMillis()
                var remaining = TimeUnit.MILLISECONDS.toNanos(input.waitMs)
                while (frames.none { it.sequence > input.afterSequence } && !isClosed.get() && remaining > 0) remaining = changed.awaitNanos(remaining)
                val page = frames.filter { it.sequence > input.afterSequence }.take(input.count)
                buildJsonObject {
                    put("connection", summary())
                    put("messages", JsonArray(page.map { it.json(includeBinary) }))
                    put("nextSequence", page.lastOrNull()?.sequence ?: input.afterSequence)
                    put("gap", frames.firstOrNull()?.sequence?.let { it > input.afterSequence + 1 } ?: false)
                }
            }
    }

    private data class Frame(
        val sequence: Long,
        val direction: String,
        val text: String?,
        val binary: kotlin.ByteArray?,
        val originalBytes: Int,
    ) {
        val size = binary?.size ?: text.orEmpty().toByteArray().size

        fun json(includeBinary: Boolean): JsonObject =
            buildJsonObject {
                put("sequence", sequence)
                put("direction", direction)
                put("type", if (binary == null) "TEXT" else "BINARY")
                put("originalBytes", originalBytes)
                put("truncated", size < originalBytes)
                text?.let { put("text", it) }
                binary?.let {
                    if (includeBinary) put("base64", Base64.getEncoder().encodeToString(it)) else put("note", "Binary body withheld while privacy mode is enabled")
                }
            }
    }
}
