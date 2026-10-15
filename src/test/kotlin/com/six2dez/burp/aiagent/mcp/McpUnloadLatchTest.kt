package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.ToolRegistry
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.anyString
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.whenever
import java.net.BindException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 gap closure (33-REVIEW WR-01) — the MCP unload latch holds even for work that passed it before
 * unload began.
 *
 * WR-01: a settings apply already in flight when `McpSupervisor.shutdown` latched must never start the
 * stdio bridge, and a bridge that was shut down starts nothing at all.
 *
 * WR-02: a start that lost its race (superseded, or binding when unload began) whose bind then fails
 * reports nothing, and a failure that reaches the supervisor after unload began never probes the port
 * holder, never POSTs `/__mcp/shutdown` to it and never schedules a restart.
 *
 * Servers bind `port = 0` (the kernel picks) or a port held open by this test for the whole case; no test
 * picks a free port itself, so the `freePort()` TOCTOU race cannot happen here.
 *
 * Naming note: this class must not end in an excluded heavy-suite suffix (IntegrationTest,
 * ConcurrencyTest, BackpressureTest, RestartPolicyTest, SupervisionTest), so it runs in the fast gate too.
 */
class McpUnloadLatchTest {
    private val bridges = CopyOnWriteArrayList<McpStdioBridge>()

    @AfterEach
    fun stopBridgesAndResetHooks() {
        // A RED run that did start a bridge must leave nothing behind.
        bridges.forEach { runCatching { it.stop(ShutdownDeadline(1_000)) } }
        KtorMcpServerManager.beforeBindForTests = null
        KtorMcpServerManager.onBoundForTests = null
    }

    @Test
    fun aSettingsApplyInFlightWhenUnloadLatchesNeverStartsTheStdioBridge() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val api = McpTestServerSupport.deepStubApi()
            val output = recordOutput(api)
            val manager = BlockingManager()
            val bridge = McpStdioBridge(api).also { bridges += it }
            val supervisor = supervisorOver(api, manager, bridge)
            val applyFailure = AtomicReference<Throwable?>()

            val applyThread =
                Thread {
                    try {
                        supervisor.applySettings(stdioSettings(), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())
                    } catch (t: Throwable) {
                        applyFailure.set(t)
                    }
                }
            applyThread.start()
            assertTrue(manager.entered.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the apply never reached the server manager")

            supervisor.shutdown(ShutdownDeadline(5_000))
            manager.release.countDown()
            applyThread.join(TimeUnit.SECONDS.toMillis(FAILSAFE_SECONDS))

            assertFalse(applyThread.isAlive, "the in-flight apply did not finish")
            assertNull(applyFailure.get(), "the in-flight apply threw instead of finishing: ${applyFailure.get()}")
            assertFalse(
                output.contains(STDIO_STARTED),
                "a settings apply in flight when unload latched started the stdio bridge after shutdown",
            )
        }
    }

    @Test
    fun aStdioBridgeStartedAfterItsShutdownStartsNothing() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val api = McpTestServerSupport.deepStubApi()
            val output = recordOutput(api)
            val bridge = McpStdioBridge(api).also { bridges += it }

            bridge.shutdown(ShutdownDeadline(1_000))
            val began = System.nanoTime()
            bridge.start(stdioSettings(), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())
            val tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)

            assertTrue(tookMs < 1_000, "a start after shutdown must return at once (took $tookMs ms)")
            assertFalse(output.contains(STDIO_STARTED), "a bridge started after its shutdown started anyway")
            bridge.stop()
            assertEquals(emptyList<String>(), output.filter { it == STDIO_STARTED })
        }
    }

    @Test
    fun aSupersededStartWhoseBindFailsReportsNoFailure() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ServerSocket(0, BACKLOG, InetAddress.getByName(LOOPBACK)).use { held ->
                val boundPorts = CopyOnWriteArrayList<Int>()
                KtorMcpServerManager.onBoundForTests = { port -> boundPorts += port }
                val holding = CountDownLatch(1)
                val releaseHold = CountDownLatch(1)
                val firstBind = AtomicBoolean(true)
                KtorMcpServerManager.beforeBindForTests = {
                    if (firstBind.compareAndSet(true, false)) {
                        holding.countDown()
                        releaseHold.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
                    }
                }
                val manager = KtorMcpServerManager(McpTestServerSupport.deepStubApi())
                val firstStates = CopyOnWriteArrayList<McpServerState>()
                val secondRunning = CountDownLatch(1)

                manager.start(McpTestServerSupport.localSettings(port = held.localPort), PrivacyMode.STRICT, false, ResponsePreprocessorSettings()) {
                    firstStates += it
                }
                assertTrue(holding.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the first start never reached its bind")
                // Supersedes the held start at once: start bumps the generation before queueing its task.
                manager.start(McpTestServerSupport.localSettings(port = 0), PrivacyMode.STRICT, false, ResponsePreprocessorSettings()) {
                    if (it is McpServerState.Running) secondRunning.countDown()
                }
                releaseHold.countDown()

                assertTrue(secondRunning.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the superseding start never reached Running")
                assertTrue(
                    firstStates.none { it is McpServerState.Failed },
                    "a superseded start whose bind failed reported Failed: $firstStates",
                )

                manager.shutdown(ShutdownDeadline(10_000))
                for (port in boundPorts) {
                    assertFalse(isListening(port), "port $port still accepts connections after shutdown returned")
                }
            }
        }
    }

    @Test
    fun aFailureReportedAfterShutdownBeganRunsNoTakeoverAndSchedulesNoRestart() {
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            val api = McpTestServerSupport.deepStubApi()
            val errors = recordErrors(api)
            val manager = CapturingManager()
            val takeover = CountingTakeover()
            val bridge = McpStdioBridge(api).also { bridges += it }
            val supervisor = supervisorOver(api, manager, bridge, takeover = takeover, restartDelayMs = 200)

            supervisor.applySettings(
                McpTestServerSupport.localSettings(port = 0).copy(enabled = true),
                PrivacyMode.STRICT,
                false,
                ResponsePreprocessorSettings(),
            )
            val callback = manager.callback.get()
            assertTrue(callback != null, "the apply never started the server")
            supervisor.shutdown(ShutdownDeadline(5_000))

            callback!!(McpServerState.Failed(BindException("Address already in use")))
            callback(McpServerState.Failed(IllegalStateException("scripted")))
            Thread.sleep(RESTART_WINDOW_MS)

            assertEquals(0, takeover.probes.get(), "a failure after unload began probed the port holder")
            assertEquals(0, takeover.shutdownRequests.get(), "a failure after unload began sent the takeover POST")
            assertEquals(1, manager.startCalls.get(), "a failure after unload began scheduled a restart")
            assertEquals(
                emptyList<String>(),
                errors.filter { it.startsWith("MCP server failed") || it.startsWith("MCP bind conflict") },
                "a failure after unload began wrote an Error line",
            )
        }
    }

    private fun recordErrors(api: MontoyaApi): MutableList<String> {
        val lines = CopyOnWriteArrayList<String>()
        val logging = api.logging()
        doAnswer { invocation ->
            lines += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyString())
        return lines
    }

    private fun isListening(port: Int): Boolean =
        try {
            Socket().use { it.connect(InetSocketAddress(LOOPBACK, port), CONNECT_TIMEOUT_MS) }
            true
        } catch (_: ConnectException) {
            false
        }

    private fun recordOutput(api: MontoyaApi): MutableList<String> {
        val lines = CopyOnWriteArrayList<String>()
        // Resolve the deep stub first: calling api.logging() inside the stubbing chain is unfinished stubbing.
        val logging = api.logging()
        doAnswer { invocation ->
            lines += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToOutput(anyString())
        return lines
    }

    private fun supervisorOver(
        api: MontoyaApi,
        manager: McpServerManager,
        bridge: McpStdioBridge,
        takeover: McpTakeoverClient = NoTakeover,
        restartDelayMs: Long = 2_000,
    ): McpSupervisor =
        McpSupervisor(
            api = api,
            serverManager = manager,
            stdioBridge = bridge,
            takeoverClientOverride = takeover,
            restartDelayMs = restartDelayMs,
        ).also { it.toolRegistry = { ToolRegistry(emptyList()) } }

    private fun stdioSettings(): McpSettings = McpTestServerSupport.localSettings(port = 0).copy(enabled = true, stdioEnabled = true)

    /** A server manager whose start blocks until the test releases it, then reports Running. */
    private class BlockingManager : McpServerManager {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)

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
            entered.countDown()
            release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
            callback(McpServerState.Running)
        }

        override fun stop(callback: (McpServerState) -> Unit) = callback(McpServerState.Stopped)

        override fun shutdown() = Unit
    }

    /** A server manager that keeps the start callback without calling it, so the test reports the outcome. */
    private class CapturingManager : McpServerManager {
        val startCalls = AtomicInteger()
        val callback = AtomicReference<((McpServerState) -> Unit)?>()

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
            this.callback.set(callback)
        }

        override fun stop(callback: (McpServerState) -> Unit) = callback(McpServerState.Stopped)

        override fun shutdown() = Unit
    }

    /** A takeover client that would find a compatible server and get it to shut down, counting each call. */
    private class CountingTakeover : McpTakeoverClient {
        val probes = AtomicInteger()
        val shutdownRequests = AtomicInteger()

        override fun probe(settings: McpSettings): Boolean {
            probes.incrementAndGet()
            return true
        }

        override fun requestShutdown(settings: McpSettings): Boolean {
            shutdownRequests.incrementAndGet()
            return true
        }
    }

    private object NoTakeover : McpTakeoverClient {
        override fun probe(settings: McpSettings): Boolean = false

        override fun requestShutdown(settings: McpSettings): Boolean = false
    }

    private companion object {
        const val FAILSAFE_SECONDS = 10L
        const val RESTART_WINDOW_MS = 600L
        const val CONNECT_TIMEOUT_MS = 1_000
        const val BACKLOG = 50
        const val LOOPBACK = "127.0.0.1"
        const val STDIO_STARTED = "MCP stdio bridge started."
    }
}
