package com.six2dez.burp.aiagent.mcp.external

import com.six2dez.burp.aiagent.audit.AuditLogger
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Reconcile saved configurations off the EDT, shared by chat and MCP contexts. */
class ExternalMcpRuntime(
    private val audit: AuditLogger,
) {
    private val closed = AtomicBoolean(false)
    private val current = AtomicReference<ExternalMcpClientManager?>(null)
    private val executor =
        Executors.newSingleThreadExecutor { task ->
            Thread(task, "burp-ai-external-mcp-settings").apply { isDaemon = true }
        }
    private var applied: List<ExternalMcpServerConfig> = emptyList()

    val manager: ExternalMcpClientManager? get() = current.get()

    @Synchronized
    fun configure(configs: List<ExternalMcpServerConfig>) {
        if (closed.get()) return
        val enabled = configs.filter { it.enabled }.toList()
        executor.execute {
            if (!closed.get() && applied != enabled) {
                current.getAndSet(null)?.stop()
                applied = enabled
                if (enabled.isNotEmpty() && !closed.get()) {
                    val replacement = ExternalMcpClientManager(auditLogger = audit)
                    current.set(replacement)
                    if (closed.get()) current.getAndSet(null)?.stop() else replacement.start(enabled)
                }
            }
        }
    }

    @Synchronized
    fun close() {
        if (!closed.compareAndSet(false, true)) return
        executor.shutdownNow()
        current.getAndSet(null)?.stop()
    }
}
