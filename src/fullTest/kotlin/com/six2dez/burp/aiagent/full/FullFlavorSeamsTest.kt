package com.six2dez.burp.aiagent.full

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.cli.CliSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.full.autoqueue.AutoQueueContribution
import com.six2dez.burp.aiagent.full.autoqueue.AutoQueuePlugin
import com.six2dez.burp.aiagent.full.autoqueue.AutoQueueSink
import com.six2dez.burp.aiagent.full.autoqueue.AutoQueueSnapshot
import com.six2dez.burp.aiagent.full.external.ExternalMcpSettings
import com.six2dez.burp.aiagent.full.external.ExternalToolProvider
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.GenericToolProvider
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.ToolProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.io.File
import java.net.URI

/**
 * Phase 29 plan 29-11 (BUILD-01, D-14, RESEARCH Pitfall 10) — what the full classpath offers, pinned.
 *
 * The full build keeps all 59 tools: the 8 native ones from the core plus the 51 generic ones that
 * [GenericToolProvider] registers through the `ToolProvider` services file in `src/full/resources`.
 * The generic aliases resolve here, and only here (StoreFlavorSeamsTest pins the store side).
 *
 * Every `com.six2dez.burp.aiagent` services file on this classpath must load through [Plugins] without
 * `ServiceConfigurationError`, which is what a Kotlin `object` provider or a missing class would raise.
 * The set of SPI files is pinned, so a new SPI has to be added here on purpose.
 *
 * Plan 29-17 (phase seal, BUILD-01, BUILD-03, BUILD-04) adds the provider census by class name for every
 * SPI, and the fresh-install edge: an empty preferences node reads the 1.0.1 CLI commands, no external
 * MCP server and the auto-queue OFF, each through the plug-in's own settings object.
 */
class FullFlavorSeamsTest {
    @Test
    fun fullCatalogHasTheFiftyNineToolsIncludingTheNativeEight() {
        val ids = McpToolCatalog.all().map { it.id }
        assertEquals(FULL_TOOL_COUNT, ids.size, "full catalog size")
        assertEquals(FULL_TOOL_COUNT, ids.toSet().size, "no tool id may appear twice: $ids")
        assertTrue(ids.containsAll(NATIVE_IDS), "the native tools are part of the full catalog")
        assertEquals(NATIVE_IDS, McpToolCatalog.coreToolIds(), "only the native tools are core tools")
    }

    @Test
    fun genericAndExternalAreTheFullBuildToolProviders() {
        val providers = Plugins.load(ToolProvider::class.java)
        // 29-15: ExternalToolProvider supplies the ext: dynamic namespace and no catalog tool.
        assertEquals(
            listOf(ExternalToolProvider::class.java.name, GenericToolProvider::class.java.name),
            providers.map { it.javaClass.name },
        )
        assertEquals(
            FULL_TOOL_COUNT - NATIVE_IDS.size,
            providers.single { it is GenericToolProvider }.handlers().size,
            "generic tool count",
        )
        assertEquals(0, providers.single { it is ExternalToolProvider }.handlers().size, "no static external tool")
    }

    @Test
    fun genericAliasesResolveOnTheFullClasspath() {
        assertEquals("proxy_http_history", McpToolExecutor.canonicalToolId("history"))
        assertEquals("site_map", McpToolExecutor.canonicalToolId("sitemap"))
        assertEquals(
            McpToolCatalog.all().single { it.id == "proxy_http_history" }.secTier,
            ToolApprovalGate.tierFor("history"),
            "an alias must resolve to its tool's tier, not the fail-closed fallback",
        )
    }

    @Test
    fun everySpiServicesFileOnTheFullClasspathLoadsThroughPlugins() {
        val servicesFiles = projectServicesFiles()
        assertEquals(EXPECTED_SPI_TYPES, servicesFiles.keys, "SPI services files on the full classpath")
        servicesFiles.forEach { (typeName, declared) ->
            val type = Class.forName(typeName)
            val loaded = Plugins.load(type).map { it.javaClass.name }
            assertEquals(declared.sorted(), loaded, "providers of $typeName")
        }
        assertEquals(1, Plugins.load(FlavorProfile::class.java).size)
        assertEquals(1, Plugins.load(AiAccessPolicy::class.java).size)
        assertTrue(Plugins.load(AiBackendFactory::class.java).isNotEmpty())
    }

    @Test
    fun everySpiLoadsExactlyTheExpectedProviderClassesOnTheFullClasspath() {
        PROVIDER_CENSUS.forEach { (type, expected) ->
            assertEquals(
                expected.sorted(),
                Plugins.load(type).map { it.javaClass.name },
                "providers of ${type.name}",
            )
        }
        assertEquals(EXPECTED_SPI_TYPES, PROVIDER_CENSUS.keys.map { it.name }.toSet(), "the census covers every SPI file")
        assertEquals(11, PROVIDER_CENSUS.getValue(AiBackendFactory::class.java).size, "6 core HTTP + 5 CLI factories")
    }

    @Test
    fun aFreshFullInstallReadsTheCliDefaultsNoExternalServerAndTheAutoQueueOff() {
        val prefs = InMemoryPreferences()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        val store = AgentSettingsRepository(api).pluginSettings()

        val cli = CliSettings(store)
        FRESH_CLI_COMMANDS.forEach { (backendId, expected) ->
            assertEquals(expected, cli.command(backendId), "$backendId command on a fresh install")
        }

        val logLines = mutableListOf<String>()
        assertEquals(emptyList<Any>(), ExternalMcpSettings(store) { logLines += it }.load(), "no external MCP server")
        assertEquals(emptyList<String>(), logLines, "an absent server list is not a parse failure")

        assertNull(store.getBoolean(AutoQueuePlugin.KEY), "a fresh install has no auto-queue value")
        assertEquals(AutoQueueSnapshot(enabled = false), AutoQueueContribution().defaults(), "the auto-queue default is OFF")
        val activeScanner = mock<ActiveAiScanner>()
        AutoQueueSink(activeScanner, store) { logLines += it }
            .offer(listOf(target()), TestSettings.baselineSettings().copy(activeAiEnabled = true))
        verifyNoInteractions(activeScanner)

        val pluginKeys = FRESH_CLI_COMMANDS.keys.mapNotNull { CliSettings.keyFor(it) } + ExternalMcpSettings.KEY + AutoQueuePlugin.KEY
        assertEquals(emptyList<String>(), prefs.writes.filter { it in pluginKeys }, "reading the defaults writes no plug-in key")
    }

    private fun target(): ActiveScanTarget =
        ActiveScanTarget(
            originalRequest = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
            injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", "1"),
            vulnHint = VulnHint(VulnClass.SQLI, 90, "evidence"),
            priority = 80,
        )

    /**
     * Every `META-INF/services/com.six2dez.burp.aiagent.*` file in the main and full production resource
     * directories, keyed by SPI type, with the provider class names it declares (comments and blank lines
     * dropped). The fullTest classpath also carries the store test resources, whose probe SPIs are test
     * fixtures and not part of either JAR, so only the two production roots are read; both must be found.
     */
    private fun projectServicesFiles(): Map<String, List<String>> {
        val result = mutableMapOf<String, MutableList<String>>()
        val roots =
            javaClass.classLoader
                .getResources(SERVICES_DIR)
                .toList()
                .filter { it.protocol == "file" && PRODUCTION_ROOT.containsMatchIn(it.path) }
        assertEquals(2, roots.size, "expected the main and full resource roots, got $roots")
        roots.forEach { url ->
            File(URI(url.toString()))
                .listFiles()
                .orEmpty()
                .filter { it.isFile && it.name.startsWith(PROJECT_PACKAGE) }
                .forEach { file ->
                    val providers =
                        file
                            .readLines()
                            .map { it.substringBefore('#').trim() }
                            .filter { it.isNotEmpty() }
                    result.getOrPut(file.name) { mutableListOf() } += providers
                }
        }
        return result
    }

    private companion object {
        const val FULL_TOOL_COUNT = 59
        const val SERVICES_DIR = "META-INF/services"
        const val PROJECT_PACKAGE = "com.six2dez.burp.aiagent."
        val PRODUCTION_ROOT = Regex("""/build/resources/(main|full)/META-INF/services/?$""")

        val NATIVE_IDS =
            setOf(
                "status",
                "issue_create",
                "ai_analyze",
                "ai_passive_scan",
                "ai_findings_recent",
                "redact_preview",
                "ai_audit_query",
                "ai_backends_list",
            )

        /** The 1.0.1 default command per CLI-owned backend id, as literals (BUILD-03 empty-input edge). */
        val FRESH_CLI_COMMANDS =
            mapOf(
                "codex-cli" to "codex chat",
                "gemini-cli" to "gemini --output-format text --model gemini-2.5-flash --yolo",
                "opencode-cli" to "opencode",
                "claude-cli" to "claude",
                "copilot-cli" to "copilot",
                "ollama" to "ollama run llama3.1",
            )

        private const val PKG = "com.six2dez.burp.aiagent"

        /** Plan 29-17: every SPI with its expected provider classes on the full classpath, by name. */
        val PROVIDER_CENSUS: Map<Class<*>, List<String>> =
            mapOf(
                AiBackendFactory::class.java to
                    listOf(
                        "$PKG.backends.anthropic.AnthropicBackendFactory",
                        "$PKG.backends.lmstudio.LmStudioBackendFactory",
                        "$PKG.backends.nvidia.NvidiaNimBackendFactory",
                        "$PKG.backends.ollama.OllamaBackendFactory",
                        "$PKG.backends.openai.OpenAiCompatibleBackendFactory",
                        "$PKG.backends.perplexity.PerplexityBackendFactory",
                        "$PKG.backends.cli.ClaudeCliBackendFactory",
                        "$PKG.backends.cli.CodexCliBackendFactory",
                        "$PKG.backends.cli.CopilotCliBackendFactory",
                        "$PKG.backends.cli.GeminiCliBackendFactory",
                        "$PKG.backends.cli.OpenCodeCliBackendFactory",
                    ),
                ToolProvider::class.java to
                    listOf(
                        "$PKG.mcp.tools.GenericToolProvider",
                        "$PKG.full.external.ExternalToolProvider",
                    ),
                SettingsContribution::class.java to
                    listOf(
                        "$PKG.full.cli.ClaudeCliContribution",
                        "$PKG.full.cli.CodexCliContribution",
                        "$PKG.full.cli.CopilotCliContribution",
                        "$PKG.full.cli.GeminiCliContribution",
                        "$PKG.full.cli.OpenCodeCliContribution",
                        "$PKG.full.cli.OllamaCliContribution",
                        "$PKG.full.external.ExternalMcpContribution",
                        "$PKG.full.autoqueue.AutoQueueContribution",
                    ),
                ExtensionPlugin::class.java to listOf("$PKG.full.autoqueue.AutoQueuePlugin"),
                AiAccessPolicy::class.java to listOf("$PKG.full.FullAiAccessPolicy"),
                FlavorProfile::class.java to listOf("$PKG.full.FullFlavorProfile"),
                BackendModelHint::class.java to listOf("$PKG.full.cli.OllamaCliModelHint"),
            )

        val EXPECTED_SPI_TYPES =
            setOf(
                "com.six2dez.burp.aiagent.backends.AiBackendFactory",
                "com.six2dez.burp.aiagent.spi.AiAccessPolicy",
                "com.six2dez.burp.aiagent.spi.BackendModelHint",
                "com.six2dez.burp.aiagent.spi.ExtensionPlugin",
                "com.six2dez.burp.aiagent.spi.FlavorProfile",
                "com.six2dez.burp.aiagent.spi.SettingsContribution",
                "com.six2dez.burp.aiagent.spi.ToolProvider",
            )
    }
}
