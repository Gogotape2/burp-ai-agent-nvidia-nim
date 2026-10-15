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
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.Executors

/**
 * Phase 33 / D-10 / LIFE-01 (T-33-28, T-33-29) — the scanner-task and Collaborator registries own no
 * thread and no executor. Expiry is lazy (an expired entry is pruned on `put` and on `get`), so touching
 * either registry never starts a thread, and with MCP disabled nothing in them ever does. Both are
 * emptied through `GenericToolProvider.onMcpServerStopped`, which `McpSupervisor.shutdown` runs at unload.
 *
 * The thread checks compare live [Thread] objects, not names, against a snapshot taken before the first
 * touch: a registry that started a worker would show up as a new thread whatever it was called.
 */
class RegistryNoThreadTest {
    @AfterEach
    fun resetRegistries() {
        ScannerTaskRegistry.clear()
        ScannerTaskRegistry.configureTtlMinutes(DEFAULT_SCAN_TTL)
        CollaboratorRegistry.clear()
        CollaboratorRegistry.configureTtlMinutes(DEFAULT_COLLABORATOR_TTL)
    }

    @Test
    fun touchingBothRegistriesStartsNoThread() {
        val before = liveThreads()

        val taskId = ScannerTaskRegistry.put(mock<ScanTask>())
        ScannerTaskRegistry.get(taskId)
        ScannerTaskRegistry.remove(taskId)
        ScannerTaskRegistry.configureTtlMinutes(DEFAULT_SCAN_TTL)
        ScannerTaskRegistry.clear()
        CollaboratorRegistry.put(COLLABORATOR_KEY, mock<CollaboratorClient>())
        CollaboratorRegistry.get(COLLABORATOR_KEY)
        CollaboratorRegistry.remove(COLLABORATOR_KEY)
        CollaboratorRegistry.configureTtlMinutes(DEFAULT_COLLABORATOR_TTL)
        CollaboratorRegistry.clear()

        val cleaners = liveThreads().map { it.name }.filter { it in LEGACY_CLEANER_NAMES }
        assertTrue(cleaners.isEmpty(), "no registry cleaner thread may exist (D-10); found $cleaners")
        val gained = liveThreads() - before
        assertTrue(gained.isEmpty(), "touching the registries must start no thread; gained ${gained.map { it.name }}")
    }

    @Test
    fun scannerTaskPutPrunesExpiredEntriesWithoutAGet() {
        ScannerTaskRegistry.configureTtlMillisForTests(1)
        ScannerTaskRegistry.put(mock<ScanTask>())
        Thread.sleep(EXPIRY_WAIT_MS)
        val taskB = mock<ScanTask>()
        val idB = ScannerTaskRegistry.put(taskB)

        assertEquals(1, ScannerTaskRegistry.sizeForTests(), "entry A must be pruned by the put of B, no get involved")
        ScannerTaskRegistry.configureTtlMinutes(DEFAULT_SCAN_TTL)
        assertSame(taskB, ScannerTaskRegistry.get(idB), "entry B is the one that stays")
    }

    @Test
    fun collaboratorPutPrunesExpiredEntriesWithoutAGet() {
        CollaboratorRegistry.configureTtlMillisForTests(1)
        CollaboratorRegistry.put("a-$COLLABORATOR_KEY", mock<CollaboratorClient>())
        Thread.sleep(EXPIRY_WAIT_MS)
        val clientB = mock<CollaboratorClient>()
        CollaboratorRegistry.put("b-$COLLABORATOR_KEY", clientB)

        assertEquals(1, CollaboratorRegistry.sizeForTests(), "entry A must be pruned by the put of B, no get involved")
        CollaboratorRegistry.configureTtlMinutes(DEFAULT_COLLABORATOR_TTL)
        assertSame(clientB, CollaboratorRegistry.get("b-$COLLABORATOR_KEY"), "entry B is the one that stays")
    }

    @Test
    fun applyingDisabledMcpSettingsStartsNoThread() {
        val prefs = InMemoryPreferences()
        val store = repository(prefs).pluginSettings()
        val before = liveThreads()

        GenericToolProvider().onMcpSettingsApplied(disabledMcpSettings(), store) {}

        val gained = liveThreads() - before
        assertTrue(gained.isEmpty(), "MCP disabled: the provider's settings hook must start no thread; gained ${gained.map { it.name }}")
    }

    @Test
    fun supervisorShutdownEmptiesBothRegistries() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        // The default tool registry: the catalog's, which in the full build loads GenericToolProvider.
        val supervisor =
            McpSupervisor(
                api = api,
                serverManager = StoppedServerManager(),
                stdioBridge = McpStdioBridge(api),
                scheduler = Executors.newSingleThreadScheduledExecutor(),
            )
        val taskId = ScannerTaskRegistry.put(mock<ScanTask>())
        CollaboratorRegistry.put(COLLABORATOR_KEY, mock<CollaboratorClient>())

        supervisor.shutdown()

        assertNull(ScannerTaskRegistry.get(taskId), "a scanner task id must not survive unload")
        assertNull(CollaboratorRegistry.get(COLLABORATOR_KEY), "a Collaborator client must not survive unload")
        assertEquals(0, ScannerTaskRegistry.sizeForTests())
        assertEquals(0, CollaboratorRegistry.sizeForTests())
    }

    private fun liveThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive }
            .toSet()

    private fun repository(prefs: InMemoryPreferences): AgentSettingsRepository {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return AgentSettingsRepository(api)
    }

    private fun disabledMcpSettings() = TestSettings.baselineSettings().mcpSettings.copy(enabled = false)

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
        const val DEFAULT_SCAN_TTL = 120
        const val DEFAULT_COLLABORATOR_TTL = 60
        const val EXPIRY_WAIT_MS = 20L
        const val COLLABORATOR_KEY = "no-thread-test-secret"
        val LEGACY_CLEANER_NAMES = setOf("McpScannerTaskRegistryCleaner", "McpCollaboratorRegistryCleaner")
    }
}
