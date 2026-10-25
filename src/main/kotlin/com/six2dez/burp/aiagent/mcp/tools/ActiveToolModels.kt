package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.Serializable

@Serializable
enum class PayloadAttackMode { SNIPER, BATTERING_RAM, PITCHFORK, CLUSTER_BOMB }

@Serializable
data class PayloadPosition(
    val marker: String,
    val payloads: List<String>,
    val baseValue: String = "",
)

@Serializable
data class IntruderAttackStart(
    val content: String,
    val positions: List<PayloadPosition>,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val mode: PayloadAttackMode = PayloadAttackMode.SNIPER,
    val maxRequests: Int = 100,
    val concurrency: Int = 1,
    val intervalMs: Long = 200,
    val timeoutMs: Long = 30_000,
    val durationMs: Long = 120_000,
    val includeBaseline: Boolean = true,
) : HttpServiceParams

@Serializable
data class IntruderAttackId(
    val attackId: String,
)

@Serializable
data class IntruderAttackResults(
    val attackId: String,
    override val offset: Int = 0,
    override val count: Int = 20,
    val includeMessages: Boolean = false,
) : Paginated

@Serializable
data class WebSocketOpen(
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean,
    val path: String = "/",
    val content: String? = null,
    val timeoutMs: Long = 15_000,
) : HttpServiceParams

@Serializable
data class WebSocketSend(
    val connectionId: String,
    val text: String? = null,
    val base64: String? = null,
    val timeoutMs: Long = 15_000,
)

@Serializable
data class WebSocketReceive(
    val connectionId: String,
    val afterSequence: Long = 0,
    val count: Int = 20,
    val waitMs: Long = 0,
)

@Serializable
data class WebSocketId(
    val connectionId: String,
)

internal object ActiveToolLimits {
    const val MIN_TIMEOUT_MS = 1000L
    const val MAX_MARKER_CHARS = 128
    const val PAYLOAD_PREVIEW_BYTES = 256
    const val WS_OPERATION_THREADS = 4
    const val WS_OPERATION_QUEUE = 16
    const val REAPER_SECONDS = 10L
    const val DEFAULT_WS_TIMEOUT_MS = 15_000L
    const val MAX_REQUESTS = 1000
    const val MAX_CONCURRENCY = 5
    const val MAX_ACTIVE_ATTACKS = 2
    const val MAX_RETAINED_ATTACKS = 8
    const val MAX_TEMPLATE_BYTES = 1_048_576
    const val MAX_PAYLOAD_BYTES = 16_384
    const val MAX_POSITIONS = 16
    const val MAX_CAPTURE_BYTES = 32_768
    const val ATTACK_STORAGE_BYTES = 4_194_304
    const val MAX_TIMEOUT_MS = 120_000L
    const val MAX_DURATION_MS = 900_000L
    const val MAX_INTERVAL_MS = 60_000L
    const val MAX_CONNECTIONS = 8
    const val MAX_RETAINED_CONNECTIONS = 16
    const val MAX_FRAME_BYTES = 65_536
    const val MAX_FRAMES = 256
    const val MAX_BUFFER_BYTES = 1_048_576
    const val MAX_PAGE = 100
    const val MAX_WAIT_MS = 30_000L
    const val IDLE_TIMEOUT_MS = 300_000L
    const val RETENTION_MS = 900_000L
}
