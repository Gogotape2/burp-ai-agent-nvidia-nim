package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit

class NimRequestCoordinatorTest {
    private fun deadline(ms: Long = 100) = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ms)

    @Test
    fun `capacity wait obeys total deadline and release frees the slot`() {
        val gate = NimRequestCoordinator()
        val options = NvidiaNimOptions(maxConcurrency = 1)
        val first = gate.acquire(options, deadline()) { false }
        assertThrows(SocketTimeoutException::class.java) { gate.acquire(options, deadline()) { false } }
        first.close()
        first.close()
        gate.acquire(options, deadline()) { false }.close()
    }

    @Test
    fun `closing the slot does not reset the sliding window quota`() {
        val gate = NimRequestCoordinator()
        val options = NvidiaNimOptions(rateLimit = 1, rateWindowSeconds = 60)
        gate.acquire(options, deadline()) { false }.close()
        assertThrows(SocketTimeoutException::class.java) { gate.acquire(options, deadline()) { false } }
    }

    @Test
    fun `provider cooldown applies across independent requests`() {
        val gate = NimRequestCoordinator()
        gate.deferFor(1000)
        assertThrows(SocketTimeoutException::class.java) { gate.acquire(NvidiaNimOptions(), deadline()) { false } }
    }

    @Test
    fun `queued cancellation does not consume capacity`() {
        val gate = NimRequestCoordinator()
        assertThrows(InterruptedException::class.java) { gate.acquire(NvidiaNimOptions(), deadline()) { true } }
        gate.acquire(NvidiaNimOptions(maxConcurrency = 1), deadline()) { false }.close()
    }
}
