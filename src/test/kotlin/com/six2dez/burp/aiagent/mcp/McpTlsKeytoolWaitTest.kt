package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Phase 34 / D-07: MCP TLS setup waits on its keytool child process with a deadline, so a hung
 * keytool cannot block setup forever. Driven against real `/bin/sh` child processes; skipped on
 * Windows, where `sh` is not available.
 */
class McpTlsKeytoolWaitTest {
    @BeforeEach
    fun skipOnWindows() {
        Assumptions.assumeFalse(
            System.getProperty("os.name").lowercase(Locale.ROOT).contains("win"),
            "the cases start /bin/sh child processes",
        )
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun aChildThatExitsReturnsItsExitCode() {
        val process = sh("exit 3")
        try {
            assertEquals(3, McpTls.awaitKeytoolExit(process, 5))
        } finally {
            process.destroyForcibly()
        }
    }

    @Test
    @Timeout(10, unit = TimeUnit.SECONDS)
    fun aHungChildIsDestroyedAtTheDeadline() {
        val process = sh("sleep 30")
        try {
            val started = System.nanoTime()
            val error = assertThrows(IllegalStateException::class.java) { McpTls.awaitKeytoolExit(process, 1) }
            val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(error.message.orEmpty().contains("within 1s"), "the message must name the deadline: ${error.message}")
            assertTrue(elapsedMs < 3_000, "the deadline must end the wait; took ${elapsedMs}ms")
            assertTrue(process.waitFor(2, TimeUnit.SECONDS), "the hung child must be destroyed")
            assertFalse(process.isAlive)
        } finally {
            process.destroyForcibly()
        }
    }

    private fun sh(script: String): Process = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true).start()
}
