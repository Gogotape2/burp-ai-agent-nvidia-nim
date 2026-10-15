package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.scanner.ScanTask
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * The MCP scanner-task registry: handles the MCP tools hand out, kept for at most the TTL.
 *
 * Phase 33 / D-10 (LIFE-01): it owns no thread and no executor. Expiry happens on access: `put` prunes
 * every expired entry before adding its own, and `get` drops an expired entry it is asked for. So touching
 * the registry never starts a thread, and with MCP disabled nothing here ever runs. The registry is
 * emptied by `GenericToolProvider.onMcpServerStopped`, both when the MCP server stops and at unload
 * (`McpSupervisor.shutdown` runs every provider's stop hook).
 */
object ScannerTaskRegistry {
    private data class TimedScanTask(
        val task: ScanTask,
        val createdAtMs: Long,
    ) {
        fun isExpired(
            nowMs: Long,
            ttlMs: Long,
        ): Boolean = nowMs - createdAtMs >= ttlMs
    }

    private val idToTask: MutableMap<String, TimedScanTask> = ConcurrentHashMap()
    private val ttlMs = AtomicLong(TimeUnit.MINUTES.toMillis(DEFAULT_TTL_MINUTES.toLong()))
    private val loggerRef = AtomicReference<(String) -> Unit>({})

    fun put(task: ScanTask): String {
        cleanupExpired()
        val id = UUID.randomUUID().toString()
        idToTask[id] = TimedScanTask(task = task, createdAtMs = System.currentTimeMillis())
        return id
    }

    fun get(id: String): ScanTask? {
        val now = System.currentTimeMillis()
        val entry = idToTask[id] ?: return null
        if (entry.isExpired(now, ttlMs.get())) {
            if (idToTask.remove(id, entry)) {
                log("Expired MCP scanner task id=$id")
            }
            return null
        }
        return entry.task
    }

    fun remove(id: String): ScanTask? = idToTask.remove(id)?.task

    fun clear() {
        idToTask.clear()
    }

    fun configureTtlMinutes(minutes: Int) {
        ttlMs.set(TimeUnit.MINUTES.toMillis(minutes.coerceIn(5, 24 * 60).toLong()))
    }

    fun setLogger(logger: (String) -> Unit) {
        loggerRef.set(logger)
    }

    internal fun configureTtlMillisForTests(milliseconds: Long) {
        ttlMs.set(milliseconds.coerceAtLeast(1L))
    }

    internal val ttlMillisForTests: Long get() = ttlMs.get()

    /** The raw entry count, expired entries included: tests read it to prove a prune happened without a `get`. */
    internal fun sizeForTests(): Int = idToTask.size

    private fun cleanupExpired() {
        val now = System.currentTimeMillis()
        var removed = 0
        val iterator = idToTask.entries.iterator()
        while (iterator.hasNext()) {
            val (id, entry) = iterator.next()
            if (entry.isExpired(now, ttlMs.get())) {
                iterator.remove()
                removed++
                log("Expired MCP scanner task id=$id")
            }
        }
        if (removed > 0) {
            log("Removed $removed expired MCP scanner task(s)")
        }
    }

    private fun log(message: String) {
        try {
            loggerRef.get().invoke(message)
        } catch (_: Exception) {
            // Ignore logging callback failures; registry behavior should stay deterministic.
        }
    }

    private const val DEFAULT_TTL_MINUTES = 120
}
