package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 / D-06 — `AgentSettings` built from its required fields only, every optional field left at
 * its declared default, survives a save and a load by a second repository over the same preferences.
 *
 * Callers (tests, plug-ins reading `coreSettings`) construct `AgentSettings` without naming the optional
 * fields. Each declared default must be a value the repository persists and reads back unchanged, except
 * the load path's documented fallbacks for a blank value, which are asserted by name below.
 */
class AgentSettingsMinimalConstructionTest {
    @Test
    fun aMinimallyConstructedSnapshotRoundTripsThroughANewRepository() {
        val prefs = InMemoryPreferences()
        val minimal = minimalSettings()

        repositoryOver(prefs).save(minimal)
        val reloaded = repositoryOver(prefs).load()

        // Load-time fallbacks for a blank value: the LM Studio server command, the MCP keystore path and its
        // generated password, and the BountyPrompt directory, whose default prompt selection comes with it.
        assertTrue(reloaded.lmStudioServerCmd.isNotBlank(), "a blank LM Studio server command reads as its default")
        assertTrue(reloaded.mcpSettings.tlsKeystorePath.isNotBlank(), "a blank keystore path reads as its default")
        assertTrue(reloaded.mcpSettings.tlsKeystorePassword.isNotBlank(), "a blank keystore password is generated")
        assertTrue(reloaded.bountyPromptDir.isNotBlank(), "a blank BountyPrompt directory reads as its default")
        assertEquals(
            minimal,
            reloaded.copy(
                lmStudioServerCmd = minimal.lmStudioServerCmd,
                mcpSettings =
                    reloaded.mcpSettings.copy(
                        tlsKeystorePath = minimal.mcpSettings.tlsKeystorePath,
                        tlsKeystorePassword = minimal.mcpSettings.tlsKeystorePassword,
                    ),
                bountyPromptDir = minimal.bountyPromptDir,
                bountyPromptEnabledPromptIds = minimal.bountyPromptEnabledPromptIds,
            ),
            "every other field, the optional defaults included, reads back unchanged",
        )
    }

    @Test
    fun theOptionalFieldsCarryTheirDeclaredDefaults() {
        val minimal = minimalSettings()
        assertEquals("https://integrate.api.nvidia.com", minimal.nvidiaNimUrl)
        assertEquals("https://api.perplexity.ai", minimal.perplexityUrl)
        assertEquals("claude-sonnet-4-6", minimal.anthropicModel)
        assertEquals(0, minimal.tokenBudgetWarnThreshold)
        assertEquals(0, minimal.tokenBudgetHardCap)
    }

    private fun repositoryOver(prefs: InMemoryPreferences): AgentSettingsRepository {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return AgentSettingsRepository(api)
    }

    private fun minimalSettings(): AgentSettings {
        val base = TestSettings.baselineSettings("ollama")
        return AgentSettings(
            agentProfile = base.agentProfile,
            ollamaModel = base.ollamaModel,
            ollamaUrl = base.ollamaUrl,
            ollamaServeCmd = base.ollamaServeCmd,
            ollamaAutoStart = base.ollamaAutoStart,
            ollamaApiKey = base.ollamaApiKey,
            ollamaHeaders = base.ollamaHeaders,
            ollamaTimeoutSeconds = base.ollamaTimeoutSeconds,
            ollamaContextWindow = base.ollamaContextWindow,
            lmStudioUrl = base.lmStudioUrl,
            lmStudioModel = base.lmStudioModel,
            lmStudioTimeoutSeconds = base.lmStudioTimeoutSeconds,
            lmStudioServerCmd = base.lmStudioServerCmd,
            lmStudioAutoStart = base.lmStudioAutoStart,
            lmStudioApiKey = base.lmStudioApiKey,
            lmStudioHeaders = base.lmStudioHeaders,
            openAiCompatibleUrl = base.openAiCompatibleUrl,
            openAiCompatibleModel = base.openAiCompatibleModel,
            openAiCompatibleApiKey = base.openAiCompatibleApiKey,
            openAiCompatibleHeaders = base.openAiCompatibleHeaders,
            openAiCompatibleTimeoutSeconds = base.openAiCompatibleTimeoutSeconds,
            requestPromptTemplate = base.requestPromptTemplate,
            issuePromptTemplate = base.issuePromptTemplate,
            issueAnalyzePrompt = base.issueAnalyzePrompt,
            issuePocPrompt = base.issuePocPrompt,
            issueImpactPrompt = base.issueImpactPrompt,
            requestSummaryPrompt = base.requestSummaryPrompt,
            explainJsPrompt = base.explainJsPrompt,
            accessControlPrompt = base.accessControlPrompt,
            loginSequencePrompt = base.loginSequencePrompt,
            hostAnonymizationSalt = base.hostAnonymizationSalt,
            preferredBackendId = base.preferredBackendId,
            privacyMode = base.privacyMode,
            determinismMode = base.determinismMode,
            auditEnabled = base.auditEnabled,
            mcpSettings = base.mcpSettings,
        )
    }
}
