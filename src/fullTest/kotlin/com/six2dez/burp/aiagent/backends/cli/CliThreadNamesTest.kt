package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpTransport
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 / D-11 / D-12 / LIFE-03 (T-33-30) — every thread the full build's CLI backend and external
 * MCP client manager create is named `burp-ai-agent-<subsystem>`, is a daemon, and comes from
 * `ExtensionThreads`; the manager's coroutines run on the extension-owned MCP dispatcher.
 *
 * Threads are found by comparing live [Thread] objects with a snapshot taken before the work starts, so
 * a same-named thread left over by another suite never satisfies a check here. Every connection and
 * manager is stopped in `finally`; nothing waits for the 30 s CLI watchdog.
 */
class CliThreadNamesTest {
    @Test
    @Timeout(TEST_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
    fun theCliConnectionAndReaderAreNamedDaemonThreadsThatStopWithTheConnection() {
        val before = liveThreads()
        val connection =
            CliBackend("ollama", "Ollama").launch(
                BackendLaunchConfig(
                    backendId = "ollama",
                    displayName = "Ollama",
                    command = sleepCommand(System.getProperty("os.name")),
                    env = emptyMap(),
                    cliTimeoutSeconds = 1,
                ),
            )
        try {
            connection.send(text = "names", history = null, onChunk = {}, onComplete = {})

            val started =
                pollUntil {
                    gained(before)
                        .filter { it.name in CLI_THREAD_NAMES }
                        .takeIf { found -> found.map { it.name }.toSet() == CLI_THREAD_NAMES }
                }
            assertNotNull(
                started,
                "a send in flight must run on burp-ai-agent-cli-connection and read on burp-ai-agent-cli-reader; " +
                    "new threads: ${gained(before).map { it.name }}",
            )
            assertTrue(started!!.all { it.isDaemon }, "both CLI threads must be daemons: ${started.map { it.name to it.isDaemon }}")
        } finally {
            connection.stop()
        }

        val leftover = pollUntil { gained(before).filter { it.name in CLI_THREAD_NAMES }.takeIf { it.isEmpty() } }
        assertNotNull(leftover, "stop() must leave no CLI thread behind: ${gained(before).map { it.name }}")
    }

    @Test
    fun theTempFileSweepHookIsTheNamedExtensionThread() {
        val workDir = Files.createTempDirectory("cli-thread-names").toFile()
        CliTempFileRegistry.resetForTests()
        try {
            CliTempFileRegistry.register(File(workDir, "prompt.txt").also { it.writeText("payload") })

            val hook = CliTempFileRegistry.hookThreadForTests()
            assertNotNull(hook, "the first temp file arms the sweep hook")
            assertEquals("burp-ai-agent-cli-temp-sweep", hook!!.name)
            assertEquals(Thread.State.NEW, hook.state, "a shutdown hook is registered unstarted")
        } finally {
            CliTempFileRegistry.shutdown()
            workDir.deleteRecursively()
        }
    }

    @Test
    @Timeout(TEST_TIMEOUT_SECONDS, unit = TimeUnit.SECONDS)
    fun theExternalManagersDefaultSchedulerAndCoroutinesAreExtensionThreads() {
        val before = liveThreads()
        val connectThread = AtomicReference<String>()
        val manager =
            ExternalMcpClientManager(
                processFactory = { _, _ ->
                    connectThread.set(Thread.currentThread().name)
                    throw IOException("no such command")
                },
            )
        try {
            manager.start(
                listOf(
                    ExternalMcpServerConfig(
                        name = "names-test",
                        transport = ExternalMcpTransport.STDIO,
                        command = listOf("does-not-exist"),
                    ),
                ),
            )

            val scheduler = pollUntil { gained(before).firstOrNull { it.name == EXTERNAL_SCHEDULER_NAME } }
            assertNotNull(
                scheduler,
                "a failed connect schedules a reconnect on burp-ai-agent-mcp-external; new threads: " +
                    "${gained(before).map { it.name }}",
            )
            assertTrue(scheduler!!.isDaemon, "the reconnect scheduler must be a daemon")
            assertTrue(
                connectThread.get().orEmpty().startsWith(MCP_COROUTINE_PREFIX),
                "the connect coroutine must run on the extension-owned MCP dispatcher, not Dispatchers.IO; " +
                    "ran on ${connectThread.get()}",
            )
        } finally {
            manager.stop()
        }
    }

    private fun liveThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive }
            .toSet()

    private fun gained(before: Set<Thread>): List<Thread> = (liveThreads() - before).toList()

    /** Polls [probe] until it returns non-null or [POLL_LIMIT_MS] passes; returns the last answer. */
    private fun <T : Any> pollUntil(probe: () -> T?): T? {
        val deadline = System.currentTimeMillis() + POLL_LIMIT_MS
        var answer = probe()
        while (answer == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(POLL_STEP_MS)
            answer = probe()
        }
        return answer
    }

    /**
     * A process that outlives the test: the connection is stopped long before it ends. Windows uses ping,
     * which ignores the redirected stdin the backend always sets up (timeout.exe exits at once on it).
     */
    private fun sleepCommand(osName: String): List<String> =
        if (osName.lowercase().contains("win")) {
            listOf("ping", "-n", "61", "127.0.0.1")
        } else {
            listOf("sleep", "60")
        }

    private companion object {
        const val TEST_TIMEOUT_SECONDS = 25L
        const val POLL_LIMIT_MS = 8_000L
        const val POLL_STEP_MS = 50L
        const val EXTERNAL_SCHEDULER_NAME = "burp-ai-agent-mcp-external"
        const val MCP_COROUTINE_PREFIX = "burp-ai-agent-mcp-coroutines"
        val CLI_THREAD_NAMES = setOf("burp-ai-agent-cli-connection", "burp-ai-agent-cli-reader")
    }
}
