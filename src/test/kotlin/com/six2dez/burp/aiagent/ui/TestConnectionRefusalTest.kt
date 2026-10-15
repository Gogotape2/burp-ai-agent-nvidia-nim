package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Phase 31 / D-12 — Test connection is a provider request, so it asks the injected policy first.
 *
 * Built on a headless [SettingsPanel] over a REAL [AgentSupervisor] and [BackendRegistry] (the store
 * classpath), so `connectionTestRefusal` is the same call `testBackendConnection` makes before it
 * starts its thread. A refusal there means no thread and no request; the GATE-01 choke point stays
 * the backstop when the policy allows.
 *
 * Phase 33 / D-11, LIFE-03, EDT-01 — an allowed Test connection runs its health check on the daemon
 * `burp-ai-agent-test-connection` thread (through `OffEdtDispatch.run`) and shows its result from the
 * EDT; the EDT stays free while the check runs. The tests run headless, so the result dialog throws
 * `HeadlessException` in the EDT tail, which `OffEdtDispatch` logs: that line proves the dialog path
 * was reached with the result.
 */
class TestConnectionRefusalTest {
    private val aiEnabled = AtomicBoolean(false)
    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val releases = CopyOnWriteArrayList<CountDownLatch>()

    @AfterEach
    fun shutdownPanels() {
        releases.forEach { it.countDown() }
        OffEdtDispatch.registerDispatchedObserver(null)
        OffEdtDispatch.registerSettledObserver(null)
        panels.forEach { it.shutdown() }
        panels.clear()
    }

    @Test
    fun anAllowedTestConnectionChecksTheBackendOnTheNamedDaemonWorkerAndLeavesTheEdtFree() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1).also { releases += it }
        val checkThread = AtomicReference<Thread?>()
        val settledOnEdt = AtomicReference<Boolean?>()
        val settled = CountDownLatch(1)
        OffEdtDispatch.registerSettledObserver { label ->
            if (label == TEST_CONNECTION_LABEL) {
                settledOnEdt.set(SwingUtilities.isEventDispatchThread())
                settled.countDown()
            }
        }
        val (panel, api) =
            newPanelWithRegistry(StoreAiAccessPolicy()) { registry ->
                doAnswer {
                    checkThread.set(Thread.currentThread())
                    entered.countDown()
                    release.await(AWAIT_SECONDS, TimeUnit.SECONDS)
                    HealthCheckResult.Unavailable("test backend down")
                }.whenever(registry).healthCheck(any(), any())
            }
        aiEnabled.set(true)

        assertTimeoutPreemptively(Duration.ofSeconds(EDT_TIMEOUT_SECONDS)) {
            SwingUtilities.invokeAndWait { panel.testBackendConnection(BACKEND_ID) }
        }
        assertTrue(entered.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the health check must run")

        val worker = checkThread.get()
        assertEquals("burp-ai-agent-test-connection", worker?.name, "the health check runs on the named worker")
        assertTrue(worker?.isDaemon == true, "the worker is daemon, not the EDT's inherited non-daemon flag")
        assertTimeoutPreemptively(Duration.ofSeconds(EDT_TIMEOUT_SECONDS), "the EDT is free while the check runs") {
            SwingUtilities.invokeAndWait {}
        }

        release.countDown()
        assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the result must come back to the EDT")
        assertEquals(true, settledOnEdt.get(), "the result path runs on the EDT")
        val tailLines = errorLines(api).filter { it.contains("$TEST_CONNECTION_LABEL failed in its EDT tail") }
        assertTrue(tailLines.any { it.contains("HeadlessException") }, "the result dialog was reached on the EDT: ${errorLines(api)}")
    }

    @Test
    fun aRefusedTestConnectionStartsNoWorkerAndSendsNothing() {
        val dispatched = CopyOnWriteArrayList<String>()
        OffEdtDispatch.registerDispatchedObserver { dispatched += it }
        val checks = CopyOnWriteArrayList<String>()
        val (panel, _) =
            newPanelWithRegistry(StoreAiAccessPolicy()) { registry ->
                doAnswer {
                    checks += it.getArgument<String>(0)
                    HealthCheckResult.Healthy
                }.whenever(registry).healthCheck(any(), any())
            }
        aiEnabled.set(false)
        val before = testConnectionThreads()

        assertTimeoutPreemptively(Duration.ofSeconds(EDT_TIMEOUT_SECONDS)) {
            // Headless: the refusal dialog throws HeadlessException on the EDT, after the refusal decision.
            SwingUtilities.invokeAndWait { runCatching { panel.testBackendConnection(BACKEND_ID) } }
        }

        assertTrue(dispatched.none { it == TEST_CONNECTION_LABEL }, "a refusal dispatches no worker: $dispatched")
        val after = testConnectionThreads()
        assertEquals(before, after, "a refusal starts no test-connection thread")
        assertTrue(checks.isEmpty(), "a refusal sends no health check: $checks")
    }

    @Test
    fun testConnectionIsRefusedWithThePolicyTextWhileUseAiIsOff() {
        val panel = newPanel(StoreAiAccessPolicy())

        aiEnabled.set(false)
        val refusal = panel.connectionTestRefusal("lmstudio")

        assertNotNull(refusal, "The store policy refuses every backend while Use AI is off.")
        assertEquals(StoreAiAccessPolicy().refusal("lmstudio", false), refusal)
    }

    @Test
    fun testConnectionIsAllowedWhileUseAiIsOn() {
        val panel = newPanel(StoreAiAccessPolicy())

        aiEnabled.set(true)

        assertNull(panel.connectionTestRefusal("lmstudio"))
    }

    @Test
    fun anUnregisteredIdIsJudgedAsBurpAi() {
        val asked = CopyOnWriteArrayList<String>()
        val recording =
            object : AiAccessPolicy {
                override fun refusal(
                    backendId: String,
                    burpAiEnabled: Boolean,
                ): String? {
                    asked.add(backendId)
                    return StoreAiAccessPolicy().refusal(backendId, burpAiEnabled)
                }
            }
        val panel = newPanel(recording)
        assertFalse(panel.backends.isRegistered(UNREGISTERED_ID), "Anti-vacuity: the CLI id must not be registered here.")

        aiEnabled.set(false)
        asked.clear()
        val refusal = panel.connectionTestRefusal(UNREGISTERED_ID)

        assertEquals(listOf(BackendRegistry.DEFAULT_BACKEND_ID), asked.toList(), "The policy must judge the resolved backend.")
        assertEquals(StoreAiAccessPolicy().refusal(BackendRegistry.DEFAULT_BACKEND_ID, false), refusal)
    }

    /** A panel over a spied real registry, so [stub] can replace `healthCheck` and record its thread. */
    private fun newPanelWithRegistry(
        policy: AiAccessPolicy,
        stub: (BackendRegistry) -> Unit,
    ): Pair<SettingsPanel, MontoyaApi> {
        val api = newApi()
        val registry = spy(BackendRegistry(api))
        stub(registry)
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), policy)
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = AgentSettingsRepository(api),
                backends = registry,
                supervisor = supervisor,
                audit = mock<AuditLogger>(),
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                buildIdentity = "Custom AI Agent test (test build)",
            )
        panels.add(panel)
        return panel to api
    }

    private fun testConnectionThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.name == "burp-ai-agent-test-connection" }
            .toSet()

    private fun errorLines(api: MontoyaApi): List<String> =
        Mockito
            .mockingDetails(api.logging())
            .invocations
            .filter { it.method.name == "logToError" }
            .map { it.arguments.first().toString() }

    private fun newPanel(policy: AiAccessPolicy): SettingsPanel {
        val api = newApi()
        val registry = BackendRegistry(api)
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), policy)
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = AgentSettingsRepository(api),
                backends = registry,
                supervisor = supervisor,
                audit = mock<AuditLogger>(),
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                buildIdentity = "Custom AI Agent test (test build)",
            )
        panels.add(panel)
        return panel
    }

    private fun newApi(): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = InMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        whenever(api.ai().isEnabled()).thenAnswer { aiEnabled.get() }
        return api
    }

    private companion object {
        const val UNREGISTERED_ID = "codex-cli"
        const val BACKEND_ID = "lmstudio"
        const val TEST_CONNECTION_LABEL = "test connection $BACKEND_ID"
        const val AWAIT_SECONDS = 15L
        const val EDT_TIMEOUT_SECONDS = 5L
    }
}
