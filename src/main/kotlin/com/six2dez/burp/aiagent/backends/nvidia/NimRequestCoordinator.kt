package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** One extension-wide gate prevents separate chat and scanner sessions multiplying the quota. */
internal class NimRequestCoordinator {
    private val lock = ReentrantLock(true)
    private val changed = lock.newCondition()
    private val starts = ArrayDeque<Long>()
    private var active = 0
    private var cooldownUntil = System.nanoTime()

    fun acquire(
        options: NvidiaNimOptions,
        deadline: Long,
        cancelled: () -> Boolean,
    ): AutoCloseable {
        lock.lockInterruptibly()
        try {
            while (true) {
                if (cancelled()) throw InterruptedException("NVIDIA NIM request cancelled")
                val now = System.nanoTime()
                val remaining = deadline - now
                if (remaining <= 0) throw SocketTimeoutException("NVIDIA NIM deadline expired while waiting for capacity")
                val window = TimeUnit.SECONDS.toNanos(options.rateWindowSeconds.toLong())
                val recent = starts.filter { now - it < window }
                if (active < options.maxConcurrency && recent.size < options.rateLimit && now >= cooldownUntil) {
                    active++
                    recordStart(now)
                    return lease()
                }
                val rateWait = if (recent.size >= options.rateLimit) recent.first() + window - now else remaining
                val cooldownWait = if (cooldownUntil > now) cooldownUntil - now else remaining
                changed.awaitNanos(minOf(remaining, rateWait, cooldownWait, TimeUnit.MILLISECONDS.toNanos(CANCELLATION_POLL_MS)).coerceAtLeast(1))
            }
        } finally {
            lock.unlock()
        }
    }

    private fun recordStart(now: Long) {
        starts.addLast(now)
        // No configured quota exceeds this ceiling; older entries cannot affect any decision.
        while (starts.size > NvidiaNimOptions.MAX_RATE_LIMIT) starts.removeFirst()
    }

    private fun lease(): AutoCloseable {
        val released = AtomicBoolean()
        return AutoCloseable {
            if (released.compareAndSet(false, true)) {
                lock.withLock {
                    active--
                    changed.signalAll()
                }
            }
        }
    }

    fun deferFor(delayMs: Long) {
        lock.withLock {
            cooldownUntil = maxOf(cooldownUntil, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(delayMs.coerceIn(0, MAX_COOLDOWN_MS)))
            changed.signalAll()
        }
    }

    companion object {
        private const val CANCELLATION_POLL_MS = 250L
        const val MAX_COOLDOWN_MS = 3_600_000L
        val shared = NimRequestCoordinator()
    }
}
