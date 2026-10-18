package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.ToolRegistry
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

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

    @Test
    fun aRestartPendingOnTheSchedulerNeverRunsAfterShutdown() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val manager = ScriptedManager { McpServerState.Failed(IllegalStateException("scripted")) }
            val supervisor = supervisorOver(manager, restartDelayMs = 300)
            supervisor.applySettings(fakeSettings(enabled = true), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())
            assertEquals(1, manager.startCalls.get(), "the first start failed and scheduled a restart")

            supervisor.shutdown(ShutdownDeadline(5_000))
            Thread.sleep(900)

            assertEquals(1, manager.startCalls.get(), "a restart pending at shutdown must never run")
        }
    }

    @Test
    fun applySettingsAfterShutdownStartsNothing() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val manager = ScriptedManager { McpServerState.Running }
            val supervisor = supervisorOver(manager)
            supervisor.shutdown(ShutdownDeadline(5_000))

            supervisor.applySettings(fakeSettings(enabled = true), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())

            assertEquals(0, manager.startCalls.get(), "a settings save landing during unload must not start the server")
        }
    }

    @Test
    fun shutdownRunsEveryProviderStopHookOnce() {
        val manager = ScriptedManager { McpServerState.Running }
        val supervisor = supervisorOver(manager)
        val recorder = StopRecordingProvider()
        supervisor.toolRegistry = { ToolRegistry(listOf(recorder)) }

        supervisor.shutdown(ShutdownDeadline(5_000))

        assertEquals(1, recorder.stops.get(), "unload must clear what MCP providers hold (onMcpServerStopped)")
    }

    @Test
    fun theDefaultSchedulerRunsRestartsOnANamedDaemonThread() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val calls = AtomicInteger()
            val manager =
                ScriptedManager {
                    if (calls.incrementAndGet() == 1) McpServerState.Failed(IllegalStateException("scripted")) else McpServerState.Running
                }
            val supervisor = supervisorOver(manager, restartDelayMs = 10)
            supervisor.applySettings(fakeSettings(enabled = true), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())

            assertTrue(manager.secondStart.await(5, TimeUnit.SECONDS), "the restart never ran")
            val thread = manager.lastStartThread.get()
            assertNotNull(thread)
            assertEquals("burp-ai-agent-mcp-supervisor", thread!!.name)
            assertTrue(thread.isDaemon, "the supervisor scheduler thread must be daemon")
            supervisor.shutdown(ShutdownDeadline(5_000))
        }
    }

    @Test
    fun tenQuickSettingsTogglesOverARealServerThenShutdownLeaveNothingListening() {
        assertTimeoutPreemptively(Duration.ofSeconds(90)) {
            val api = McpTestServerSupport.deepStubApi()
            val supervisor =
                McpSupervisor(
                    api = api,
                    serverManager = KtorMcpServerManager(api),
                    stdioBridge = McpStdioBridge(api),
                    takeoverClientOverride = NoTakeover,
                )
            repeat(TOGGLES) { i ->
                supervisor.applySettings(
                    McpTestServerSupport.localSettings(port = 0).copy(enabled = i % 2 == 0),
                    PrivacyMode.STRICT,
                    false,
                    ResponsePreprocessorSettings(),
                )
            }
            supervisor.shutdown(ShutdownDeadline(10_000))

            assertNoRecordedPortListens()
        }
    }

    @Test
    fun theStdioCloseBudgetIsCappedByTheDeadline() {
        assertEquals(5_000L, McpStdioBridge.closeTimeoutMs(null))
        assertEquals(5_000L, McpStdioBridge.closeTimeoutMs(ShutdownDeadline(60_000)))
        assertEquals(0L, McpStdioBridge.closeTimeoutMs(ShutdownDeadline(0)))
        assertTrue(McpStdioBridge.closeTimeoutMs(ShutdownDeadline(1_000)) <= 1_000L)

        val bridge = McpStdioBridge(McpTestServerSupport.deepStubApi())
        val began = System.nanoTime()
        bridge.stop(ShutdownDeadline(0))
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 1_000, "an expired deadline must not wait")
    }

    private fun supervisorOver(
        manager: McpServerManager,
        restartDelayMs: Long = 2_000,
    ): McpSupervisor {
        val api = McpTestServerSupport.deepStubApi()
        return McpSupervisor(
            api = api,
            serverManager = manager,
            stdioBridge = McpStdioBridge(api),
            takeoverClientOverride = NoTakeover,
            restartDelayMs = restartDelayMs,
        ).also { it.toolRegistry = { ToolRegistry(emptyList()) } }
    }

    private fun fakeSettings(enabled: Boolean): McpSettings = McpTestServerSupport.localSettings(port = 0).copy(enabled = enabled)

    /** A server manager that answers every start with [next]; counts starts and records the starting thread. */
    private class ScriptedManager(
        private val next: () -> McpServerState,
    ) : McpServerManager {
        val startCalls = AtomicInteger()
        val lastStartThread = AtomicReference<Thread?>()
        val secondStart = CountDownLatch(2)

        override fun setAiRequestLogger(logger: AiRequestLogger) = Unit

        override fun setAiToolDependencies(
            supervisor: AgentSupervisor,
            passiveScanner: PassiveAiScanner,
            backendRegistry: BackendRegistry,
        ) = Unit

        override fun start(
            settings: McpSettings,
            privacyMode: PrivacyMode,
            determinismMode: Boolean,
            preprocessSettings: ResponsePreprocessorSettings,
            callback: (McpServerState) -> Unit,
        ) {
            startCalls.incrementAndGet()
            lastStartThread.set(Thread.currentThread())
            secondStart.countDown()
            callback(next())
        }

        override fun stop(callback: (McpServerState) -> Unit) = callback(McpServerState.Stopped)

        override fun shutdown() = Unit
    }

    private class StopRecordingProvider : ToolProvider {
        val stops = AtomicInteger()

        override fun handlers(): List<ToolHandler> = emptyList()

        override fun onMcpServerStopped() {
            stops.incrementAndGet()
        }
    }

    private object NoTakeover : McpTakeoverClient {
        override fun probe(settings: McpSettings): Boolean = false

        override fun requestShutdown(settings: McpSettings): Boolean = false
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
