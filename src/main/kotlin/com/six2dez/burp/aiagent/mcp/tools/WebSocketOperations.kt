package com.six2dez.burp.aiagent.mcp.tools

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** A timed-out vendor API call may still return a socket; dispose it rather than leaking its lease. */
internal class WebSocketOperations : AutoCloseable {
    private val executor =
        ThreadPoolExecutor(
            ActiveToolLimits.WS_OPERATION_THREADS,
            ActiveToolLimits.WS_OPERATION_THREADS,
            0,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(ActiveToolLimits.WS_OPERATION_QUEUE),
            { task -> Thread(task, "ai-websocket-operation").apply { isDaemon = true } },
        )

    fun execute(action: () -> Unit) {
        executor.execute(action)
    }

    fun <T : Any> run(
        timeout: Long,
        onSkipped: () -> Unit = {},
        disposeLate: (T) -> Unit = {},
        action: () -> T,
    ): T {
        val result = CompletableFuture<T>()
        try {
            executor.execute {
                if (result.isDone) onSkipped() else complete(result, action, disposeLate)
            }
        } catch (e: RejectedExecutionException) {
            onSkipped()
            throw e
        }
        return await(result, timeout, disposeLate)
    }

    // Montoya transports can throw implementation-specific exceptions; preserve them across the worker boundary.
    @Suppress("TooGenericExceptionCaught")
    private fun <T : Any> complete(
        result: CompletableFuture<T>,
        action: () -> T,
        disposeLate: (T) -> Unit,
    ) {
        try {
            val value = action()
            if (!result.complete(value)) disposeLate(value)
        } catch (e: Exception) {
            result.completeExceptionally(e)
        }
    }

    // These distinct exceptions need different cleanup and interrupt handling, while retaining their causes.
    @Suppress("ThrowsCount")
    private fun <T : Any> await(
        result: CompletableFuture<T>,
        timeout: Long,
        disposeLate: (T) -> Unit,
    ): T {
        try {
            return result.get(timeout, TimeUnit.MILLISECONDS)
        } catch (e: ExecutionException) {
            throw (e.cause as? Exception ?: IllegalStateException("WebSocket operation failed", e))
        } catch (e: TimeoutException) {
            abandon(result, disposeLate)
            throw IllegalStateException("WebSocket operation timed out; delivery outcome may be unknown. Inspect connection/messages before retrying.", e)
        } catch (e: InterruptedException) {
            abandon(result, disposeLate)
            Thread.currentThread().interrupt()
            throw e
        }
    }

    private fun <T : Any> abandon(
        result: CompletableFuture<T>,
        disposeLate: (T) -> Unit,
    ) {
        if (!result.cancel(false)) runCatching { result.getNow(null)?.let(disposeLate) }
    }

    override fun close() {
        executor.shutdown()
    }
}
