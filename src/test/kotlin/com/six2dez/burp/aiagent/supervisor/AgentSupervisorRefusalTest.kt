package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Phase 31 / GATE-01, D-16 — the shared refusal helpers later plans build on:
 * [AgentSupervisor.refusalForSavedBackend] judges the backend the supervisor would really run (an
 * unregistered saved id runs on burp-ai), and [AgentSupervisor.aiToolRefusal] adds the requirement
 * that Burp's "Use AI" is on to whatever the injected policy says.
 */
class AgentSupervisorRefusalTest {
    private val aiEnabled = AtomicBoolean(false)
    private val logging = mock<Logging>()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    init {
        whenever(api.logging()).thenReturn(logging)
        whenever(api.persistence().preferences()).thenReturn(InMemoryPreferences())
        whenever(api.ai().isEnabled()).thenAnswer { aiEnabled.get() }
    }

    @Test
    fun refusalForAnUnregisteredSavedIdJudgesBurpAiAndLogsTheSubstitutionOnce() {
        val supervisor = supervisor(StoreAiAccessPolicy())

        val first = supervisor.refusalForSavedBackend(UNREGISTERED_ID)
        val second = supervisor.refusalForSavedBackend(UNREGISTERED_ID)

        assertNotNull(first, "the store policy refuses while Use AI is off")
        assertEquals(supervisor.aiAccessRefusal(BackendRegistry.DEFAULT_BACKEND_ID), first)
        assertEquals(first, second)
        verify(logging, times(1)).logToOutput(
            "[AgentSupervisor] Saved backend '$UNREGISTERED_ID' is not registered in this build; using burp-ai.",
        )
    }

    @Test
    fun aiToolRefusalIsTheStoreTextWhileUseAiIsOffAndNullWhileItIsOn() {
        val supervisor = supervisor(StoreAiAccessPolicy())
        supervisor.applySettings(TestSettings.baselineSettings("lmstudio"))

        aiEnabled.set(false)
        assertEquals(StoreAiAccessPolicy().refusal("lmstudio", false), supervisor.aiToolRefusal())

        aiEnabled.set(true)
        assertNull(supervisor.aiToolRefusal())
    }

    @Test
    fun aiToolRefusalRequiresUseAiOnTopOfAPolicyThatAllowsEveryBackend() {
        val supervisor = supervisor(ALLOW_EVERY_BACKEND)
        supervisor.applySettings(TestSettings.baselineSettings("lmstudio"))

        aiEnabled.set(false)
        assertEquals(AgentSupervisor.AI_TOOLS_REQUIRE_BURP_AI, supervisor.aiToolRefusal())

        aiEnabled.set(true)
        assertNull(supervisor.aiToolRefusal())
    }

    private fun supervisor(policy: AiAccessPolicy): AgentSupervisor = AgentSupervisor(api, BackendRegistry(api), mock<AuditLogger>(), policy)

    private companion object {
        const val UNREGISTERED_ID = "some-unregistered-id"

        val ALLOW_EVERY_BACKEND =
            object : AiAccessPolicy {
                override fun refusal(
                    backendId: String,
                    burpAiEnabled: Boolean,
                ): String? = null
            }
    }
}
