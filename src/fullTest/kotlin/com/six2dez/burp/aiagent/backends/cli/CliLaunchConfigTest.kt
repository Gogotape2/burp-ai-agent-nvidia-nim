package com.six2dez.burp.aiagent.backends.cli

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.full.FullAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.TokenTracker
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.io.File
import java.util.ServiceLoader

/**
 * Phase 29 / D-09: the CLI launch dialect moved from the core supervisor's `when` branches onto
 * [CliBackend.launchConfig]. These tests pin that every CLI id still launches with the 1.0.1
 * configuration when it goes through the supervisor and a registry built from the full build's merged
 * services, and that the CLI temp-file shutdown still runs on unload.
 */
class CliLaunchConfigTest {
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)

    @AfterEach
    fun leaveRegistryClean() {
        CliTempFileRegistry.shutdown()
    }

    @Test
    fun mergedServicesRegisterTheSixCoreAndFiveCliFactories() {
        val factories =
            ServiceLoader
                .load(AiBackendFactory::class.java, AiBackendFactory::class.java.classLoader)
                .map { it.javaClass.simpleName }
                .sorted()
        assertEquals(
            listOf(
                "AnthropicBackendFactory",
                "ClaudeCliBackendFactory",
                "CodexCliBackendFactory",
                "CopilotCliBackendFactory",
                "GeminiCliBackendFactory",
                "LmStudioBackendFactory",
                "NvidiaNimBackendFactory",
                "OllamaBackendFactory",
                "OpenAiCompatibleBackendFactory",
                "OpenCodeCliBackendFactory",
                "PerplexityBackendFactory",
            ),
            factories,
            "the full classpath merges core's 6 HTTP factories and src/full's 5 CLI factories",
        )
        val ids = BackendRegistry(api).listAllBackendIds()
        assertEquals(12, ids.size, "full build: burp-ai + 6 HTTP + 5 CLI ids, got $ids")
        assertTrue(ids.containsAll(CLI_COMMANDS.keys), "every CLI id must be registered in the full build, got $ids")
    }

    @Test
    fun everyCliIdLaunchesWithThe101ConfigWhenMcpIsOff() {
        val settings = cliSettings(mcpEnabled = false)
        CLI_COMMANDS.keys.forEach { id ->
            val config = supervisorLaunchConfig(settings, id, cliSessionId = "resume-$id")
            assertEquals(expected101Config(settings, id, cliSessionId = "resume-$id"), config, "$id launch config")
            assertFalse(config.env.keys.any { it.contains("MCP") }, "$id: no MCP variable while MCP is off")
        }
    }

    @Test
    fun everyCliIdLaunchesWithTheMcpVariablesWhenMcpIsOn() {
        val settings = cliSettings(mcpEnabled = true)
        CLI_COMMANDS.keys.forEach { id ->
            val config = supervisorLaunchConfig(settings, id, cliSessionId = null)
            assertEquals(expected101Config(settings, id, cliSessionId = null), config, "$id launch config")
            assertEquals("http://127.0.0.1:8765/mcp", config.env["MCP_SERVER_URL"], "$id: MCP server URL")
            assertEquals("token", config.env["BURP_MCP_TOKEN"], "$id: MCP token")
        }
    }

    @Test
    fun anHttpBackendLaunchConfigCarriesNoCliEnvironment() {
        // T-29-23: the login-shell PATH capture and the CLI variables run only for a CLI backend.
        val config = supervisorLaunchConfig(cliSettings(mcpEnabled = true), "ollama", cliSessionId = null)
        assertEquals(
            setOf("BURP_AI_AGENT_SESSION_ID", "BURP_AI_AGENT_DETERMINISM"),
            config.env.keys,
            "an HTTP backend gets the session and determinism variables only",
        )
    }

    @Test
    fun theLaunchedProcessTimeoutIsClampedToTheWatchdogRange() {
        val backend = BackendRegistry(api).get("codex-cli")!!
        val low = backend.launch(BackendLaunchConfig("codex-cli", "Codex CLI", command = listOf("codex"), cliTimeoutSeconds = 5))
        val high = backend.launch(BackendLaunchConfig("codex-cli", "Codex CLI", command = listOf("codex"), cliTimeoutSeconds = 99_999))
        try {
            assertEquals(30, timeoutOf(low), "a sub-30s timeout is raised to the 30s floor")
            assertEquals(3600, timeoutOf(high), "a timeout above an hour is cut to 3600s")
        } finally {
            low.stop()
            high.stop()
        }
    }

    @Test
    fun registryShutdownRunsTheCliTempFileShutdown() {
        val registry = BackendRegistry(api)
        val file = File.createTempFile("burp-ai-agent-cli-launch-test", ".txt")
        CliTempFileRegistry.register(file)
        assertTrue(CliTempFileRegistry.isHookRegisteredForTests(), "precondition: registering a file arms the exit hook")

        registry.shutdown()

        assertFalse(file.exists(), "BackendRegistry.shutdown() must drain the CLI temp files")
        assertEquals(0, CliTempFileRegistry.sizeForTests())
        assertFalse(CliTempFileRegistry.isHookRegisteredForTests(), "the exit hook must be unregistered on unload (T-24-07)")
    }

    @Test
    fun cliBackendsKeepTheir101HealthLocalityAndTokenRatios() {
        val registry = BackendRegistry(api)
        CLI_COMMANDS.keys.forEach { id ->
            assertTrue(registry.get(id)!!.healthCheckIsLocal, "$id: a CLI health check is a local process probe")
        }
        assertEquals(3.5, registry.get("claude-cli")!!.charsPerTokenEstimate)
        assertEquals(3.7, registry.get("gemini-cli")!!.charsPerTokenEstimate)
        listOf("codex-cli", "opencode-cli", "copilot-cli").forEach { id ->
            assertNull(registry.get(id)!!.charsPerTokenEstimate, "$id uses the core default ratio")
        }
        // BackendRegistry.reload() publishes the ratios to the estimator.
        assertEquals(10, TokenTracker.estimateTokens(35, "claude-cli"))
        assertEquals(10, TokenTracker.estimateTokens(37, "gemini-cli"))
        assertEquals(9, TokenTracker.estimateTokens(35, "codex-cli"))
    }

    @Test
    fun cliConfigurationErrorsAreThe101MainTabMessages() {
        val registry = BackendRegistry(api)
        val blank =
            TestSettings.baselineSettings().copy(codexCmd = " ", geminiCmd = "", opencodeCmd = "", claudeCmd = "", copilotCmd = "")
        assertEquals("Codex command is empty.", registry.get("codex-cli")!!.configurationError(blank))
        assertEquals("Gemini command is empty.", registry.get("gemini-cli")!!.configurationError(blank))
        assertEquals("OpenCode command is empty.", registry.get("opencode-cli")!!.configurationError(blank))
        assertEquals("Claude command is empty.", registry.get("claude-cli")!!.configurationError(blank))
        assertEquals("Copilot command is empty.", registry.get("copilot-cli")!!.configurationError(blank))

        val configured = cliSettings(mcpEnabled = false)
        CLI_COMMANDS.keys.forEach { id ->
            assertNull(registry.get(id)!!.configurationError(configured), "$id: a configured command is valid")
        }

        val openCode = registry.get("opencode-cli") as CliBackend
        val bareExe = configured.copy(opencodeCmd = "opencode.exe")
        assertEquals(
            "OpenCode command looks like a bare .exe. If installed via npm, use 'opencode' (without .exe) or a full path to opencode.cmd.",
            openCode.configurationErrorFor(bareExe, isWindows = true),
        )
        assertNull(openCode.configurationErrorFor(bareExe, isWindows = false), "the hint is Windows-only")
        assertNull(openCode.configurationErrorFor(configured.copy(opencodeCmd = "C:\\npm\\opencode.exe"), isWindows = true))
    }

    private fun supervisorLaunchConfig(
        settings: AgentSettings,
        backendId: String,
        cliSessionId: String?,
    ): BackendLaunchConfig {
        val supervisor = AgentSupervisor(api, BackendRegistry(api), mock<AuditLogger>(), FullAiAccessPolicy())
        supervisor.applySettings(settings)
        val method =
            AgentSupervisor::class.java.getDeclaredMethod(
                "buildLaunchConfig",
                String::class.java,
                String::class.java,
                String::class.java,
            )
        method.isAccessible = true
        return method.invoke(supervisor, backendId, SESSION_ID, cliSessionId) as BackendLaunchConfig
    }

    private fun expected101Config(
        settings: AgentSettings,
        id: String,
        cliSessionId: String?,
    ): BackendLaunchConfig {
        val mcp = settings.mcpSettings
        val mcpUrl = "http://${mcp.host}:${mcp.port}/mcp"
        val mcpEnv =
            if (mcp.enabled) {
                mapOf(
                    "BURP_MCP_PORT" to mcp.port.toString(),
                    "BURP_MCP_HOST" to mcp.host,
                    "BURP_MCP_TOKEN" to mcp.token,
                    "BURP_MCP_API_URL" to mcpUrl,
                    "MCP_SERVER_URL" to mcpUrl,
                    "MCP_SERVER" to mcpUrl,
                    "MCP_TOKEN" to mcp.token,
                )
            } else {
                emptyMap()
            }
        val env =
            mapOf(
                "BURP_AI_AGENT_SESSION_ID" to SESSION_ID,
                "BURP_AI_AGENT_DETERMINISM" to settings.determinismMode.toString(),
                "PATH" to CliEnvironment.buildCliPathStatic(),
            ) + mcpEnv +
                mapOf(
                    "CI" to "1",
                    "TERM" to "dumb",
                    "NO_COLOR" to "1",
                    "CLICOLOR" to "0",
                    "FORCE_COLOR" to "0",
                    "BURP_AI_AGENT_EMBEDDED" to "1",
                )
        val (displayName, tokens) = EXPECTED[id]!!
        return BackendLaunchConfig(
            backendId = id,
            displayName = displayName,
            command = tokens,
            sessionId = SESSION_ID,
            determinismMode = settings.determinismMode,
            env = env,
            cliSessionId = cliSessionId,
            cliTimeoutSeconds = settings.cliTimeoutSeconds,
        )
    }

    private fun cliSettings(mcpEnabled: Boolean): AgentSettings {
        val base = TestSettings.baselineSettings()
        return base.copy(
            codexCmd = CLI_COMMANDS.getValue("codex-cli"),
            geminiCmd = CLI_COMMANDS.getValue("gemini-cli"),
            opencodeCmd = CLI_COMMANDS.getValue("opencode-cli"),
            claudeCmd = CLI_COMMANDS.getValue("claude-cli"),
            copilotCmd = CLI_COMMANDS.getValue("copilot-cli"),
            determinismMode = true,
            cliTimeoutSeconds = 450,
            mcpSettings = base.mcpSettings.copy(enabled = mcpEnabled),
        )
    }

    private fun timeoutOf(connection: Any): Int {
        val field = connection.javaClass.getDeclaredField("cliTimeoutSeconds")
        field.isAccessible = true
        return field.getInt(connection)
    }

    private companion object {
        const val SESSION_ID = "session-cli-launch-test"

        val CLI_COMMANDS =
            linkedMapOf(
                "codex-cli" to "  codex exec --full-auto ",
                "gemini-cli" to "gemini --model 'gemini 2.5'",
                "opencode-cli" to "opencode run",
                "claude-cli" to "claude -p --verbose",
                "copilot-cli" to "copilot",
            )

        // The 1.0.1 supervisor branches: display name and the trimmed, tokenized command per id.
        val EXPECTED =
            mapOf(
                "codex-cli" to ("Codex CLI" to listOf("codex", "exec", "--full-auto")),
                "gemini-cli" to ("Gemini CLI" to listOf("gemini", "--model", "gemini 2.5")),
                "opencode-cli" to ("OpenCode CLI" to listOf("opencode", "run")),
                "claude-cli" to ("Claude Code" to listOf("claude", "-p", "--verbose")),
                "copilot-cli" to ("Copilot CLI" to listOf("copilot")),
            )
    }
}
