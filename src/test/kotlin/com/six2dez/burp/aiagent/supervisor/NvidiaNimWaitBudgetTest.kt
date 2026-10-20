package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.Executors

class NvidiaNimWaitBudgetTest {
    @Test
    fun nimCallersWaitForConfiguredDeadlineWhileOtherBackendsKeepTheirBudget() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = mock<BackendRegistry>()
        whenever(registry.listAllBackendIds()).thenReturn(emptyList())
        val pool = Executors.newSingleThreadExecutor()
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), pool)
        try {
            val settings = TestSettings.baselineSettings().copy(preferredBackendId = "nvidia-nim", nvidiaNimTimeoutSeconds = 900)
            supervisor.applySettings(settings)
            assertEquals(905_000L, supervisor.responseWaitTimeoutMs(15_000))
            assertEquals(905_000L, supervisor.responseWaitTimeoutMs(90_000))
            assertEquals(905_000L, supervisor.responseWaitTimeoutMs(120_000))
            supervisor.applySettings(settings.copy(preferredBackendId = "ollama"))
            assertEquals(90_000L, supervisor.responseWaitTimeoutMs(90_000))
        } finally {
            supervisor.shutdown()
            pool.shutdownNow()
        }
    }
}
