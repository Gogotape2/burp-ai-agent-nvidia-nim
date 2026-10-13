package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.scanner.ScanTask
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.McpServerManager
import com.six2dez.burp.aiagent.mcp.McpServerState
import com.six2dez.burp.aiagent.mcp.McpStdioBridge
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Phase 29 / D-15, D-06 (T-29-40) — the generic provider owns the scanner-task and Collaborator
 * registries: it reads their TTLs from its own preference keys through [PluginSettingsStore], clamps
 * them to 5..1440 minutes, never writes those keys, and clears both registries when the MCP server
 * stops. `McpSupervisor` reaches it only through the [ToolProvider] lifecycle hooks, in registry order.
 *
 * Lives in src/fullTest from the start: the generic provider moves to src/full in plan 29-11, and
 * fullTest compiles against main + full, so this test never has to move.
 *
 * The suppressions: detekt's default test excludes match only directories named `test`, not src/fullTest, so the
 * rules they waive for tests are waived here explicitly; literal TTL values are what the tests assert.
 */
@Suppress("TooManyFunctions", "MagicNumber")
class GenericToolProviderLifecycleTest {
    @AfterEach
    fun resetRegistries() {
        ScannerTaskRegistry.clear()
        ScannerTaskRegistry.configureTtlMinutes(DEFAULT_SCAN_TTL)
        CollaboratorRegistry.clear()
        CollaboratorRegistry.configureTtlMinutes(DEFAULT_COLLABORATOR_TTL)
    }

    @Test
    fun withNoStoredKeysTheProviderConfiguresTheDefaultTtls() {
        val (store, _) = newStore()
        ScannerTaskRegistry.configureTtlMinutes(30)
        CollaboratorRegistry.configureTtlMinutes(30)

        GenericToolProvider().onMcpSettingsApplied(mcpSettings(), store) {}

        assertEquals(minutes(DEFAULT_SCAN_TTL), ScannerTaskRegistry.ttlMillisForTests)
        assertEquals(minutes(DEFAULT_COLLABORATOR_TTL), CollaboratorRegistry.ttlMillisForTests)
    }

    @Test
    fun aStoredValueInRangeAppliesVerbatimSoA101InstallKeepsItsTtls() {
        val (store, prefs) = newStore()
        prefs.integers[SCAN_TTL_KEY] = 90
        prefs.integers[COLLABORATOR_TTL_KEY] = 45

        GenericToolProvider().onMcpSettingsApplied(mcpSettings(), store) {}

        assertEquals(minutes(90), ScannerTaskRegistry.ttlMillisForTests)
        assertEquals(minutes(45), CollaboratorRegistry.ttlMillisForTests)
    }

    @Test
    fun storedValuesOutsideTheRangeAreClampedTo5And1440() {
        val (store, prefs) = newStore()
        prefs.integers[SCAN_TTL_KEY] = 4
        prefs.integers[COLLABORATOR_TTL_KEY] = 1441

        GenericToolProvider().onMcpSettingsApplied(mcpSettings(), store) {}

        assertEquals(minutes(5), ScannerTaskRegistry.ttlMillisForTests)
        assertEquals(minutes(1440), CollaboratorRegistry.ttlMillisForTests)

        prefs.integers[SCAN_TTL_KEY] = 1441
        prefs.integers[COLLABORATOR_TTL_KEY] = 4
        GenericToolProvider().onMcpSettingsApplied(mcpSettings(), store) {}

        assertEquals(minutes(1440), ScannerTaskRegistry.ttlMillisForTests)
        assertEquals(minutes(5), CollaboratorRegistry.ttlMillisForTests)
    }

    @Test
    fun neitherTheProviderNorACoreSaveWritesOrDeletesTheTtlKeys() {
        val (store, prefs) = newStore()
        prefs.integers[SCAN_TTL_KEY] = 4
        prefs.integers[COLLABORATOR_TTL_KEY] = 1441
        val repo = repository(prefs)

        GenericToolProvider().onMcpSettingsApplied(mcpSettings(), store) {}
        repo.save(repo.defaultSettings())
        repo.load()

        for (key in listOf(SCAN_TTL_KEY, COLLABORATOR_TTL_KEY)) {
            assertEquals(0, prefs.writeCount(key), "$key must never be written (D-08): the provider only reads it")
            assertEquals(0, prefs.deleteCount(key), "$key must never be deleted (D-08)")
        }
        assertEquals(4, prefs.integers[SCAN_TTL_KEY], "the stored value stays exactly as the user left it")
        assertEquals(1441, prefs.integers[COLLABORATOR_TTL_KEY])
    }

    @Test
    fun onMcpServerStoppedClearsBothRegistries() {
        val task = mock<ScanTask>()
        val client = mock<CollaboratorClient>()
        val taskId = ScannerTaskRegistry.put(task)
        CollaboratorRegistry.put(COLLABORATOR_SECRET, client)
        assertSame(task, ScannerTaskRegistry.get(taskId))
        assertSame(client, CollaboratorRegistry.get(COLLABORATOR_SECRET))

        GenericToolProvider().onMcpServerStopped()

        assertNull(ScannerTaskRegistry.get(taskId), "a scanner task id must not outlive the server")
        assertNull(CollaboratorRegistry.get(COLLABORATOR_SECRET), "a Collaborator client must not outlive the server")
    }

    @Test
    fun theSupervisorCallsBothHooksOnEveryProviderInRegistryOrder() {
        val events = CopyOnWriteArrayList<String>()
        val (store, prefs) = newStore()
        prefs.integers[SCAN_TTL_KEY] = 90
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = ToolRegistry(listOf(P3Recording(events), NativeToolProvider(), P2Recording(events), GenericToolProvider()))
        val supervisor = newSupervisor(api, registry)
        supervisor.setPluginSettings(store)
        val taskId = ScannerTaskRegistry.put(mock())

        // enabled = false: applySettings runs the settings hooks, then stop(), which runs the stop hooks.
        supervisor.applySettings(mcpSettings(), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())

        assertEquals(
            listOf("P2:applied", "P3:applied", "P2:stopped", "P3:stopped"),
            events,
            "every provider gets the settings hook, in registry order, before any gets the stop hook",
        )
        assertEquals(minutes(90), ScannerTaskRegistry.ttlMillisForTests, "the supervisor reaches the generic provider")
        assertNull(ScannerTaskRegistry.get(taskId), "the supervisor's stop reaches the generic provider")
        verify(api.logging()).logToOutput("[P2] settings applied")
        supervisor.shutdown()
    }

    @Test
    fun aThrowingProviderIsLoggedAndDoesNotStopTheOthers() {
        val events = CopyOnWriteArrayList<String>()
        val (store, _) = newStore()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = ToolRegistry(listOf(NativeToolProvider(), P1Throwing(), P2Recording(events)))
        val supervisor = newSupervisor(api, registry)
        supervisor.setPluginSettings(store)

        supervisor.applySettings(mcpSettings(), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())

        assertEquals(listOf("P2:applied", "P2:stopped"), events)
        verify(api.logging()).logToError(
            "MCP tool provider ${P1Throwing::class.java.name} failed in onMcpSettingsApplied: boom-applied",
        )
        verify(api.logging()).logToError(
            "MCP tool provider ${P1Throwing::class.java.name} failed in onMcpServerStopped: boom-stopped",
        )
        supervisor.shutdown()
    }

    @Test
    fun withoutAPluginSettingsStoreOnlyTheStopHookRuns() {
        val events = CopyOnWriteArrayList<String>()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val supervisor = newSupervisor(api, ToolRegistry(listOf(NativeToolProvider(), P2Recording(events))))

        supervisor.applySettings(mcpSettings(), PrivacyMode.STRICT, false, ResponsePreprocessorSettings())

        assertTrue(events.none { it.endsWith(":applied") }, "no store, no settings hook: $events")
        assertEquals(listOf("P2:stopped"), events)
        supervisor.shutdown()
    }

    private fun newStore(): Pair<PluginSettingsStore, InMemoryPreferences> {
        val prefs = InMemoryPreferences()
        return repository(prefs).pluginSettings() to prefs
    }

    private fun repository(prefs: InMemoryPreferences): AgentSettingsRepository {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return AgentSettingsRepository(api)
    }

    private fun newSupervisor(
        api: MontoyaApi,
        registry: ToolRegistry,
    ): McpSupervisor =
        McpSupervisor(
            api = api,
            serverManager = StoppedServerManager(),
            stdioBridge = McpStdioBridge(api),
            scheduler = Executors.newSingleThreadScheduledExecutor(),
        ).also { it.toolRegistry = { registry } }

    private fun mcpSettings(): McpSettings = TestSettings.baselineSettings().mcpSettings.copy(enabled = false)

    private fun minutes(value: Int): Long = TimeUnit.MINUTES.toMillis(value.toLong())

    /** Records its hook calls. Class names order the plug-in providers in the registry (P1 < P2 < P3). */
    private open class Recording(
        private val label: String,
        private val events: MutableList<String>,
    ) : ToolProvider {
        override fun handlers(): List<ToolHandler> = emptyList()

        override fun onMcpSettingsApplied(
            settings: McpSettings,
            pluginSettings: PluginSettingsStore,
            log: (String) -> Unit,
        ) {
            events += "$label:applied"
            log("[$label] settings applied")
        }

        override fun onMcpServerStopped() {
            events += "$label:stopped"
        }
    }

    private class P2Recording(
        events: MutableList<String>,
    ) : Recording("P2", events)

    private class P3Recording(
        events: MutableList<String>,
    ) : Recording("P3", events)

    private class P1Throwing : ToolProvider {
        override fun handlers(): List<ToolHandler> = emptyList()

        override fun onMcpSettingsApplied(
            settings: McpSettings,
            pluginSettings: PluginSettingsStore,
            log: (String) -> Unit,
        ): Unit = error("boom-applied")

        override fun onMcpServerStopped(): Unit = error("boom-stopped")
    }

    private class StoppedServerManager : McpServerManager {
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
        ) = callback(McpServerState.Stopped)

        override fun stop(callback: (McpServerState) -> Unit) = callback(McpServerState.Stopped)

        override fun shutdown() = Unit
    }

    private companion object {
        const val SCAN_TTL_KEY = "mcp.scan.task.ttl.minutes"
        const val COLLABORATOR_TTL_KEY = "mcp.collaborator.ttl.minutes"
        const val DEFAULT_SCAN_TTL = 120
        const val DEFAULT_COLLABORATOR_TTL = 60
        const val COLLABORATOR_SECRET = "lifecycle-test-secret"
    }
}
