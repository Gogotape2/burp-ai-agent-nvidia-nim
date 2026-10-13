package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TestTransports
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.config.SeverityLevel
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PayloadRisk
import com.six2dez.burp.aiagent.scanner.ScanMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.ConcurrentHashMap

class BackendHealthCheckTest {
    @Test
    fun healthCheckUsesExplicitBackendSignal() {
        val registry = createRegistry()
        val map = backendsField(registry)
        map.clear()
        map["test"] =
            FakeBackend(
                id = "test",
                health = HealthCheckResult.Degraded("Auth token rejected."),
                available = true,
            )

        val result = registry.healthCheck("test", baselineSettings())
        assertTrue(result is HealthCheckResult.Degraded)
        assertEquals("Auth token rejected.", (result as HealthCheckResult.Degraded).message)
    }

    @Test
    fun healthCheckFallsBackToAvailabilityForUnknown() {
        val registry = createRegistry()
        val map = backendsField(registry)
        map.clear()
        map["ok"] =
            FakeBackend(
                id = "ok",
                health = HealthCheckResult.Unknown,
                available = true,
            )
        map["bad"] =
            FakeBackend(
                id = "bad",
                health = HealthCheckResult.Unknown,
                available = false,
            )

        val settings = baselineSettings()
        val okResult = registry.healthCheck("ok", settings)
        val badResult = registry.healthCheck("bad", settings)

        assertTrue(okResult is HealthCheckResult.Healthy)
        assertTrue(badResult is HealthCheckResult.Unavailable)
    }

    @Test
    fun anUnknownHealthIsTheGateRefusalWhenTheTransportRefuses() {
        // Phase 31 / GATE-01 (Pitfall 4): Anthropic-style Unknown must not read "Connection OK."
        // while the egress gate refuses.
        val registry = createRegistry { api -> TestTransports.refusing(api, REFUSAL) }
        val map = backendsField(registry)
        map.clear()
        map["ok"] = FakeBackend(id = "ok", health = HealthCheckResult.Unknown, available = true)

        assertEquals(HealthCheckResult.Unavailable(REFUSAL), registry.healthCheck("ok", baselineSettings()))
    }

    @Test
    fun anUnknownHealthIsUnavailableWhenNoTransportWasEverSet() {
        val registry = createRegistry { null }
        val map = backendsField(registry)
        map.clear()
        map["ok"] = FakeBackend(id = "ok", health = HealthCheckResult.Unknown, available = true)

        val result = registry.healthCheck("ok", baselineSettings())
        assertTrue(result is HealthCheckResult.Unavailable, "expected Unavailable, got $result")
        assertTrue((result as HealthCheckResult.Unavailable).message.contains("MontoyaHttpTransport unavailable"))
    }

    @Test
    fun aRefusingTransportLeavesNonUnknownResultsUntouched() {
        val registry = createRegistry { api -> TestTransports.refusing(api, REFUSAL) }
        val map = backendsField(registry)
        map.clear()
        map["degraded"] = FakeBackend(id = "degraded", health = HealthCheckResult.Degraded("Auth token rejected."), available = true)

        assertEquals(HealthCheckResult.Degraded("Auth token rejected."), registry.healthCheck("degraded", baselineSettings()))
    }

    @Test
    fun healthCheckReturnsUnavailableForMissingBackend() {
        val registry = createRegistry()
        val result = registry.healthCheck("does-not-exist", baselineSettings())
        assertTrue(result is HealthCheckResult.Unavailable)
        assertTrue((result as HealthCheckResult.Unavailable).message.contains("does-not-exist"))
    }

    // Defaults to an allowing transport, so the Unknown mapping tests keep their pre-Phase-31 meaning.
    private fun createRegistry(transport: (MontoyaApi) -> MontoyaHttpTransport? = { TestTransports.open(it) }): BackendRegistry {
        val api = mock<MontoyaApi>()
        val logging = mock<Logging>()
        whenever(api.logging()).thenReturn(logging)
        val registry = BackendRegistry(api)
        transport(api)?.let { registry.setHttpTransport(it) }
        return registry
    }

    @Suppress("UNCHECKED_CAST")
    private fun backendsField(registry: BackendRegistry): ConcurrentHashMap<String, AiBackend> {
        val field = registry.javaClass.getDeclaredField("backends")
        field.isAccessible = true
        return field.get(registry) as ConcurrentHashMap<String, AiBackend>
    }

    private fun baselineSettings(): AgentSettings =
        AgentSettings(
            agentProfile = "pentester",
            ollamaModel = "llama3.1:8b",
            ollamaUrl = "http://127.0.0.1:11434",
            ollamaServeCmd = "ollama serve",
            ollamaAutoStart = false,
            ollamaApiKey = "",
            ollamaHeaders = "",
            ollamaTimeoutSeconds = 60,
            ollamaContextWindow = 8192,
            lmStudioUrl = "http://127.0.0.1:1234",
            lmStudioModel = "model",
            lmStudioTimeoutSeconds = 60,
            lmStudioServerCmd = "",
            lmStudioAutoStart = false,
            lmStudioApiKey = "",
            lmStudioHeaders = "",
            openAiCompatibleUrl = "",
            openAiCompatibleModel = "",
            openAiCompatibleApiKey = "",
            openAiCompatibleHeaders = "",
            openAiCompatibleTimeoutSeconds = 60,
            requestPromptTemplate = "req",
            issuePromptTemplate = "issue",
            issueAnalyzePrompt = "analyze",
            issuePocPrompt = "poc",
            issueImpactPrompt = "impact",
            requestSummaryPrompt = "summary",
            explainJsPrompt = "js",
            accessControlPrompt = "access",
            loginSequencePrompt = "login",
            hostAnonymizationSalt = "salt",
            preferredBackendId = "codex-cli",
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            auditEnabled = true,
            mcpSettings =
                McpSettings(
                    enabled = false,
                    host = "127.0.0.1",
                    port = 8765,
                    externalEnabled = false,
                    stdioEnabled = false,
                    token = "token",
                    allowedOrigins = emptyList(),
                    tlsEnabled = false,
                    tlsAutoGenerate = true,
                    tlsKeystorePath = "",
                    tlsKeystorePassword = "",
                    maxConcurrentRequests = 4,
                    maxBodyBytes = 262_144,
                    toolToggles = emptyMap(),
                    enabledUnsafeTools = emptySet(),
                    unsafeEnabled = false,
                ),
            passiveAiEnabled = false,
            passiveAiRateSeconds = 5,
            passiveAiScopeOnly = true,
            passiveAiMaxSizeKb = 96,
            passiveAiMinSeverity = SeverityLevel.LOW,
            activeAiEnabled = false,
            activeAiMaxConcurrent = 2,
            activeAiMaxPayloadsPerPoint = 8,
            activeAiTimeoutSeconds = 30,
            activeAiRequestDelayMs = 100,
            activeAiMaxRiskLevel = PayloadRisk.SAFE,
            activeAiScopeOnly = true,
            activeAiScanMode = ScanMode.FULL,
            activeAiUseCollaborator = false,
            bountyPromptEnabled = false,
            bountyPromptDir = "",
            bountyPromptAutoCreateIssues = true,
            bountyPromptIssueConfidenceThreshold = 90,
            bountyPromptEnabledPromptIds = emptySet(),
        )

    private companion object {
        const val REFUSAL = "refused by the test gate"
    }

    private class FakeBackend(
        override val id: String,
        private val health: HealthCheckResult,
        private val available: Boolean,
    ) : AiBackend {
        override val displayName: String = id

        override fun launch(config: BackendLaunchConfig): AgentConnection = throw UnsupportedOperationException("Not needed for this test")

        override fun isAvailable(settings: AgentSettings): Boolean = available

        override fun healthCheck(settings: AgentSettings): HealthCheckResult = health
    }
}
