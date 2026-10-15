package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.Socket
import java.net.URLClassLoader
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Phase 33 / D-12 — the coroutine work this extension starts runs on a dispatcher it owns and closes at
 * unload, and the one irreversible shared shutdown is fenced by a classloader guard.
 *
 * NEVER call `McpCoroutines.shutdownSharedDispatchers` or `Dispatchers.shutdown()` here: it is
 * irreversible and would break every later test in this shared JVM that touches Ktor or coroutines. Only
 * the guard is tested here; the call itself runs in the dedicated unloadLeakTest JVM.
 */
class McpCoroutinesTest {
    private val logged = CopyOnWriteArrayList<String>()

    @AfterEach
    fun resetHook() {
        KtorMcpServerManager.onBoundForTests = null
    }

    @Test
    fun theDispatcherRunsOnNamedDaemonThreadsThatCloseStopsAndIsRecreatedAfterwards() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val thread = runBlocking { withContext(McpCoroutines.dispatcher()) { Thread.currentThread() } }
            assertTrue(thread.name.startsWith(COROUTINE_THREAD_PREFIX), "ran on ${thread.name}")
            assertTrue(thread.isDaemon, "the MCP coroutine threads must be daemon")

            McpCoroutines.close(ShutdownDeadline(5_000)) { logged += it }

            awaitNoLiveThread { it.name.startsWith(COROUTINE_THREAD_PREFIX) }
            assertTrue(logged.isEmpty(), "a clean close writes nothing, got $logged")

            val again = runBlocking { withContext(McpCoroutines.dispatcher()) { Thread.currentThread().name } }
            assertTrue(again.startsWith(COROUTINE_THREAD_PREFIX), "the next dispatcher() must work again, ran on $again")
            McpCoroutines.close(ShutdownDeadline(5_000)) { logged += it }
        }
    }

    @Test
    fun theSharedShutdownIsAllowedOnlyForTheExtensionsOwnLoader() {
        val a = URLClassLoader(emptyArray(), null)
        val b = URLClassLoader(emptyArray(), null)
        a.use {
            b.use {
                assertTrue(McpCoroutines.shouldShutdownShared(a, a))
                assertFalse(McpCoroutines.shouldShutdownShared(a, b))
                assertFalse(McpCoroutines.shouldShutdownShared(null, a))
                assertFalse(McpCoroutines.shouldShutdownShared(a, null))
                assertFalse(McpCoroutines.shouldShutdownShared(null, null))
            }
        }
    }

    @Test
    fun aServedRequestThenShutdownAndCloseLeaveNoMcpThreadAlive() {
        assertTimeoutPreemptively(Duration.ofSeconds(60)) {
            val before = mcpThreads()
            val ports = CopyOnWriteArrayList<Int>()
            KtorMcpServerManager.onBoundForTests = { ports += it }
            val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())
            val running = CountDownLatch(1)
            manager.start(
                McpTestServerSupport.localSettings(port = 0),
                PrivacyMode.STRICT,
                determinismMode = false,
                preprocessSettings = ResponsePreprocessorSettings(),
            ) { state -> if (state is McpServerState.Running) running.countDown() }
            assertTrue(running.await(10, TimeUnit.SECONDS), "the server never reached Running")

            val status = healthStatus(ports.single())
            assertEquals(200, status)
            val servedOnOwnDispatcher = liveThreads().count { it.name.startsWith(COROUTINE_THREAD_PREFIX) }
            // RESEARCH assumption A5: recorded, not asserted. Printed into the JUnit XML's system-out.
            println("A5: live $COROUTINE_THREAD_PREFIX* threads after one served request = $servedOnOwnDispatcher")

            manager.shutdown(ShutdownDeadline(10_000))
            McpCoroutines.close(ShutdownDeadline(5_000)) { logged += it }

            awaitNoLiveThread { it.name.startsWith(COROUTINE_THREAD_PREFIX) }
            awaitNoLiveThread { it.name.startsWith(MCP_THREAD_PREFIX) && it !in before }
        }
    }

    /**
     * GET /__mcp/health over a raw socket, with a port-less `Host`. Not HttpURLConnection: the local-mode
     * gate compares a Host port with the configured port (0 here, which it treats as malformed), and the
     * JDK client always sends the real port. A port-less loopback Host skips that comparison.
     */
    private fun healthStatus(port: Int): Int =
        Socket("127.0.0.1", port).use { socket ->
            socket.soTimeout = 2_000
            socket.getOutputStream().write(
                "GET /__mcp/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII),
            )
            val statusLine =
                socket
                    .getInputStream()
                    .bufferedReader(Charsets.US_ASCII)
                    .readLine()
                    .orEmpty()
            statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: -1
        }

    private fun liveThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive }
            .toSet()

    private fun mcpThreads(): Set<Thread> = liveThreads().filter { it.name.startsWith(MCP_THREAD_PREFIX) }.toSet()

    private fun awaitNoLiveThread(matches: (Thread) -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if (liveThreads().none(matches)) return
            Thread.sleep(20)
        }
        val left = liveThreads().filter(matches).map { it.name }
        assertTrue(left.isEmpty(), "threads outlived the close: $left")
    }

    private companion object {
        const val COROUTINE_THREAD_PREFIX = "burp-ai-agent-mcp-coroutines-"
        const val MCP_THREAD_PREFIX = "burp-ai-agent-mcp-"
    }
}
