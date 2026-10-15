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
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 gap closure (33-REVIEW WR-01) — the MCP unload latch holds even for work that passed it before
 * unload began.
 *
 * WR-01: a settings apply already in flight when `McpSupervisor.shutdown` latched must never start the
 * stdio bridge, and a bridge that was shut down starts nothing at all.
 *
 * Naming note: this class must not end in an excluded heavy-suite suffix (IntegrationTest,
 * ConcurrencyTest, BackpressureTest, RestartPolicyTest, SupervisionTest), so it runs in the fast gate too.
 */
class McpUnloadLatchTest {
    private val bridges = CopyOnWriteArrayList<McpStdioBridge>()

    @AfterEach
    fun stopBridges() {
        // A RED run that did start a bridge must leave nothing behind.
        bridges.forEach { runCatching { it.stop(ShutdownDeadline(1_000)) } }
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

    private object NoTakeover : McpTakeoverClient {
        override fun probe(settings: McpSettings): Boolean = false

        override fun requestShutdown(settings: McpSettings): Boolean = false
    }

    private companion object {
        const val FAILSAFE_SECONDS = 10L
        const val STDIO_STARTED = "MCP stdio bridge started."
    }
}
