package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Phase 33 / D-08 / SC2 — the MCP listener lifecycle is one serialized state machine, so a stop or an
 * unload always wins over a pending start and nothing listens on an MCP port after shutdown returns.
 *
 * Every server here binds `port = 0`: the kernel picks the port and [KtorMcpServerManager.onBoundForTests]
 * reports it. No test picks a port itself, so the `freePort()` bind-and-close TOCTOU race of the older MCP
 * tests cannot happen here. Each port the manager ever bound is then probed with a plain TCP connect, which
 * must be refused.
 *
 * Naming note: this class must not end in an excluded heavy-suite suffix (IntegrationTest,
 * ConcurrencyTest, BackpressureTest, RestartPolicyTest, SupervisionTest), so it runs in the fast gate too.
 */
class McpLifecycleSerializationTest {
    private val boundPorts = CopyOnWriteArrayList<Int>()

    @BeforeEach
    fun recordBoundPorts() {
        KtorMcpServerManager.onBoundForTests = { port -> boundPorts += port }
    }

    @AfterEach
    fun resetHook() {
        KtorMcpServerManager.onBoundForTests = null
    }

    @Test
    fun aStartRacingAShutdownLeavesNothingListening() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val before = lifecycleThreads()
            val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())

            startOnPortZero(manager) { }
            manager.shutdown(ShutdownDeadline(10_000))

            assertNoRecordedPortListens()
            awaitNoNewLifecycleThread(before)
        }
    }

    @Test
    fun tenQuickTogglesThenShutdownLeaveNothingListening() {
        assertTimeoutPreemptively(Duration.ofSeconds(60)) {
            val before = lifecycleThreads()
            val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())
            var starts = 0

            repeat(TOGGLES) { i ->
                if (i % 2 == 0) {
                    starts++
                    startOnPortZero(manager) { }
                } else {
                    manager.stop { }
                }
            }
            manager.shutdown(ShutdownDeadline(10_000))

            assertNoRecordedPortListens()
            assertTrue(boundPorts.size <= starts, "bound ${boundPorts.size} ports for $starts start calls")
            awaitNoNewLifecycleThread(before)
        }
    }

    @Test
    fun aRunningServerIsClosedByShutdownAndALaterStartBindsNothing() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())
            val running = CountDownLatch(1)
            startOnPortZero(manager) { state ->
                if (state is McpServerState.Running) running.countDown()
            }
            assertTrue(running.await(10, TimeUnit.SECONDS), "the server never reached Running")
            assertEquals(1, boundPorts.size, "a Running server must have reported its bound port")
            assertTrue(isListening(boundPorts.single()), "the Running server must accept connections")

            manager.shutdown(ShutdownDeadline(10_000))
            assertNoRecordedPortListens()

            val afterShutdown = CopyOnWriteArrayList<McpServerState>()
            startOnPortZero(manager) { state -> afterShutdown += state }
            Thread.sleep(300)
            assertEquals(1, boundPorts.size, "a start after shutdown must not bind")
            assertTrue(
                afterShutdown.isNotEmpty() &&
                    afterShutdown.last().let { it is McpServerState.Stopped || it is McpServerState.Failed },
                "a start after shutdown must report Stopped or Failed, got $afterShutdown",
            )
        }
    }

    @Test
    fun theNoArgumentShutdownStillClosesTheServer() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())
            val running = CountDownLatch(1)
            startOnPortZero(manager) { state ->
                if (state is McpServerState.Running) running.countDown()
            }
            assertTrue(running.await(10, TimeUnit.SECONDS), "the server never reached Running")

            manager.shutdown()

            assertNoRecordedPortListens()
        }
    }

    private fun startOnPortZero(
        manager: KtorMcpServerManager,
        callback: (McpServerState) -> Unit,
    ) {
        manager.start(
            McpTestServerSupport.localSettings(port = 0),
            PrivacyMode.STRICT,
            determinismMode = false,
            preprocessSettings = ResponsePreprocessorSettings(),
            callback = callback,
        )
    }

    private fun assertNoRecordedPortListens() {
        for (port in boundPorts) {
            assertTrue(!isListening(port), "port $port still accepts connections after shutdown returned")
        }
    }

    private fun isListening(port: Int): Boolean =
        try {
            Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS) }
            true
        } catch (_: ConnectException) {
            false
        }

    private fun lifecycleThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.name == LIFECYCLE_THREAD }
            .toSet()

    private fun awaitNoNewLifecycleThread(before: Set<Thread>) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (System.nanoTime() < deadline) {
            if ((lifecycleThreads() - before).none { it.isAlive }) return
            Thread.sleep(20)
        }
        val left = (lifecycleThreads() - before).filter { it.isAlive }
        assertTrue(left.isEmpty(), "a $LIFECYCLE_THREAD thread outlived shutdown: $left")
    }

    private companion object {
        const val LIFECYCLE_THREAD = "burp-ai-agent-mcp-lifecycle"
        const val TOGGLES = 10
        const val CONNECT_TIMEOUT_MS = 1_000
    }
}
