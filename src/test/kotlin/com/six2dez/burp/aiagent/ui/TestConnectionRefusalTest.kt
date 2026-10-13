package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
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
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 31 / D-12 — Test connection is a provider request, so it asks the injected policy first.
 *
 * Built on a headless [SettingsPanel] over a REAL [AgentSupervisor] and [BackendRegistry] (the store
 * classpath), so `connectionTestRefusal` is the same call `testBackendConnection` makes before it
 * starts its thread. A refusal there means no thread and no request; the GATE-01 choke point stays
 * the backstop when the policy allows.
 */
class TestConnectionRefusalTest {
    private val aiEnabled = AtomicBoolean(false)
    private val panels = CopyOnWriteArrayList<SettingsPanel>()

    @AfterEach
    fun shutdownPanels() {
        panels.forEach { it.shutdown() }
        panels.clear()
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
    }
}
