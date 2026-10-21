package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import java.net.SocketTimeoutException
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Enforce a wall-clock deadline even if a native transport call fails to return on time. */
internal class NimHttpCall(
    private val coordinator: NimRequestCoordinator,
) {
    // Each async failure needs a distinct translation while preserving its cause.
    @Suppress("ThrowsCount")
    fun post(
        transport: MontoyaHttpTransport,
        endpoint: String,
        headers: Map<String, String>,
        json: String,
        options: NvidiaNimOptions,
        deadline: Long,
        onSending: () -> Unit = {},
        cancelled: () -> Boolean,
    ): TransportResponse {
        val future =
            try {
                workers.submit<TransportResponse> {
                    // The worker owns the lease: native calls ignoring interruption keep their slot
                    // until they actually finish, preventing cancellation from oversubscribing NIM.
                    coordinator.acquire(options, deadline, cancelled).use {
                        if (cancelled() || Thread.currentThread().isInterrupted) throw CancellationException("NVIDIA NIM request cancelled")
                        val remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).coerceAtLeast(1)
                        onSending()
                        transport.post(endpoint, headers, json, remainingMs)
                    }
                }
            } catch (e: RejectedExecutionException) {
                throw IllegalStateException("NVIDIA NIM transport workers are busy. Wait for earlier requests to finish.", e)
            }
        try {
            return future.get((deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS)
        } catch (e: TimeoutException) {
            future.cancel(true)
            throw SocketTimeoutException("NVIDIA NIM total deadline expired while waiting for Burp's HTTP transport").apply { initCause(e) }
        } catch (e: InterruptedException) {
            future.cancel(true)
            throw e
        } catch (e: ExecutionException) {
            throw e.cause ?: e
        }
    }

    companion object {
        // No unbounded queue or immortal per-request threads; idle daemon workers expire.
        private val workers =
            ThreadPoolExecutor(
                0,
                32,
                60L,
                TimeUnit.SECONDS,
                SynchronousQueue(),
                { task -> Thread(task, "nvidia-nim-http").apply { isDaemon = true } },
            )
    }
}
