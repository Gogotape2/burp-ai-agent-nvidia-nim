package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettings
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** The five-second UI timer must not submit inference or join the provider request queue. */
internal class NimHealthSnapshot(
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private class Entry(
        val key: List<String>,
        val result: HealthCheckResult,
        val checkedAt: Long,
    )

    private val latest = AtomicReference<Entry?>()

    fun record(
        settings: AgentSettings,
        result: HealthCheckResult,
    ): HealthCheckResult {
        latest.set(Entry(key(settings), result, nanoTime()))
        return result
    }

    fun current(settings: AgentSettings): HealthCheckResult {
        val entry = latest.get()
        if (entry != null && entry.key == key(settings) && nanoTime() - entry.checkedAt < MAX_AGE_NANOS) return entry.result
        return HealthCheckResult.Degraded("NIM has not been tested recently. Use Test connection or send a chat message. Background status never submits generation requests.")
    }

    private fun key(settings: AgentSettings): List<String> = listOf(settings.nvidiaNimUrl.trim(), settings.nvidiaNimModel.trim(), settings.nvidiaNimApiKey, settings.nvidiaNimHeaders)

    companion object {
        private val MAX_AGE_NANOS = TimeUnit.MINUTES.toNanos(5)
    }
}
