package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.SuggestedTarget
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.ExtensionPlugin
import com.six2dez.burp.aiagent.spi.ExternalBackendSource
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.io.File

/**
 * Phase 29 plan 29-11 (BUILD-01 empty-provider edge, D-14, D-16) — what the store classpath offers, pinned.
 *
 * Since plan 29-11 the generic MCP tools, their helpers and the scanner / collaborator registries are
 * compiled only from `src/full`, and the `ToolProvider` services file lives in `src/full/resources`. On
 * the store classpath (`src/main` + `src/test`, the input of the BApp Store JAR) the tool catalog is
 * therefore exactly the 8 native tools, and every seam falls back to its core default.
 *
 * This replaces `McpToolCatalogStoreBuildTest`, which plan 29-08 removed together with the store-build
 * filter. FullFlavorSeamsTest (src/fullTest) pins the full classpath side.
 *
 * T-29-22: a prompt-injected generic tool name in the store build is not an alias, is not in the catalog,
 * resolves to the fail-closed CONFIRM_EACH tier, and the executor answers "Unknown tool".
 *
 * Plan 29-17 (phase seal) adds the final store-side census: no provider for any of the six plug-in SPIs,
 * the six HTTP backend factories as the only AiBackendFactory providers, and a registry of exactly those
 * six backends plus Burp AI.
 *
 * Phase 31 / D-14 (GATE-03, WR-05, ADR-18 OQ8) adds the drop-in loader proofs: no ExternalBackendSource
 * provider, a registry that holds no file or class loader and creates no directory across reloads, and
 * a source guard that no core file names the drop-in directory or opens a URL class loader.
 *
 * Phase 32 SC1 extends the passive-path guards: no active-scanner field on the passive scanner, the
 * suggested-target list or its entries, and no active-scanner name or queue call in any passive-path file.
 */
class StoreFlavorSeamsTest {
    @Test
    fun storeCatalogIsExactlyTheEightNativeTools() {
        val ids = McpToolCatalog.all().map { it.id }
        assertEquals(NATIVE_IDS, ids.toSet(), "store catalog must be exactly the native tools")
        assertEquals(NATIVE_IDS.size, ids.size, "no tool id may appear twice: $ids")
        assertEquals(NATIVE_IDS, McpToolCatalog.coreToolIds(), "every store tool is a core tool")
    }

    @Test
    fun storeClasspathHasNoToolProvider() {
        assertTrue(
            Plugins.load(ToolProvider::class.java).isEmpty(),
            "the ToolProvider services file must not be on the store classpath",
        )
    }

    @Test
    fun storeClasspathHasNoExtensionPlugin() {
        assertTrue(
            Plugins.load(ExtensionPlugin::class.java).isEmpty(),
            "the ExtensionPlugin services file must not be on the store classpath (no passive-to-active auto-queue)",
        )
    }

    @Test
    fun storeClasspathHasNoProviderForAnyPluginSpi() {
        val spis =
            listOf(
                ToolProvider::class.java,
                SettingsContribution::class.java,
                ExtensionPlugin::class.java,
                BackendModelHint::class.java,
                FlavorProfile::class.java,
                AiAccessPolicy::class.java,
                ExternalBackendSource::class.java,
            )
        spis.forEach { type ->
            assertEquals(
                emptyList<String>(),
                Plugins.load(type).map { it.javaClass.name },
                "no ${type.simpleName} provider may be on the store classpath",
            )
        }
    }

    @Test
    fun storeBackendsAreExactlyTheSixHttpFactoriesPlusBurpAi() {
        assertEquals(
            STORE_FACTORIES,
            Plugins.load(AiBackendFactory::class.java).map { it.javaClass.name },
            "the store AiBackendFactory providers",
        )
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = BackendRegistry(api)
        try {
            assertEquals(
                listOf("anthropic", "burp-ai", "lmstudio", "nvidia-nim", "ollama", "openai-compatible", "perplexity"),
                registry.listAllBackendIds().sorted(),
                "the store registry",
            )
        } finally {
            registry.shutdown()
        }
    }

    /**
     * Phase 31 / D-14 (GATE-03 idempotency edge): the store registry holds no file and no class loader,
     * and two reloads leave the same seven ids without creating anything under the home directory.
     * `user.home` points at a @TempDir for the duration, so the real home is never touched.
     */
    @Test
    fun storeRegistryHoldsNoDropInStateAndReloadsCreateNoDirectory(
        @TempDir home: File,
    ) {
        val loaderFields =
            BackendRegistry::class.java.declaredFields
                .filter { field ->
                    field.type == File::class.java || ClassLoader::class.java.isAssignableFrom(field.type)
                }.map { "${it.name}: ${it.type.name}" }
        assertEquals(emptyList<String>(), loaderFields, "BackendRegistry fields typed File or ClassLoader")

        val savedHome = System.getProperty("user.home")
        System.setProperty("user.home", home.absolutePath)
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = BackendRegistry(api)
        try {
            val initial = registry.listAllBackendIds().sorted()
            repeat(2) { registry.reload() }

            assertEquals(STORE_BACKEND_IDS, initial, "the store registry after construction")
            assertEquals(STORE_BACKEND_IDS, registry.listAllBackendIds().sorted(), "the store registry after two reloads")
            assertEquals(emptyList<String>(), home.list().orEmpty().toList(), "nothing created under the home directory")
        } finally {
            registry.shutdown()
            System.setProperty("user.home", savedHome)
        }
    }

    /**
     * Phase 31 / D-14 (GATE-03, T-31-21): no core file names the drop-in directory or opens a URL class
     * loader. The walk is limited to the core root, so the full build's loader in src/full is allowed.
     */
    @Test
    fun coreHoldsNoDropInLoader() {
        val mainRoot = SourceRoots.root(SourceRoots.MAIN).canonicalFile.toPath()
        val coreFiles = SourceRoots.kotlinFiles().filter { it.canonicalFile.toPath().startsWith(mainRoot) }
        assertTrue(coreFiles.isNotEmpty(), "the core walk found no Kotlin file")

        val hits = coreFiles.flatMap { dropInLoaderHits(SourceRoots.relativePath(it), it.readLines()) }

        assertEquals(emptyList<String>(), hits, "core must hold no drop-in loader")
    }

    @Test
    fun dropInLoaderMatcherReportsEveryTokenWithFileAndLine() {
        val synthetic =
            listOf(
                "package x",
                "val dir = File(home, \"$DROP_IN_DIR\")",
                "val cl = $URL_CLASS_LOADER(urls, parent)",
                "val clean = 1",
            )

        assertEquals(
            listOf("x/Synthetic.kt:2: $DROP_IN_DIR", "x/Synthetic.kt:3: $URL_CLASS_LOADER"),
            dropInLoaderHits("x/Synthetic.kt", synthetic),
            "the fail-first case: both tokens are reported as file:line",
        )
    }

    private fun dropInLoaderHits(
        path: String,
        lines: List<String>,
    ): List<String> =
        lines.flatMapIndexed { index, line ->
            DROP_IN_TOKENS.filter { it in line }.map { "$path:${index + 1}: $it" }
        }

    /**
     * Plan 29-16 / D-02, T-29-33: the passive scanner offers suggested targets only to an optional
     * SuggestedTargetSink, so it must hold no reference through which it could queue target traffic.
     * Phase 32 SC1 extends the guard to the core list and its entries, which hold the same targets.
     */
    @Test
    fun suggestionPathDeclaresNoActiveScannerField() {
        val activeTyped =
            listOf(PassiveAiScanner::class.java, SuggestedTargetList::class.java, SuggestedTarget::class.java)
                .flatMap { start -> generateSequence<Class<*>>(start) { it.superclass }.toList() }
                .flatMap { it.declaredFields.asList() }
                .filter { ActiveAiScanner::class.java.isAssignableFrom(it.type) }
                .map { "${it.declaringClass.simpleName}.${it.name}" }
        assertEquals(emptyList<String>(), activeTyped, "suggestion-path fields typed as the active scanner")
    }

    /**
     * Phase 32 SC1 (T-32-01): no passive-path file names the active scanner class or any of its queue
     * calls, comments included, so the passive check has no code path that queues target traffic.
     */
    @Test
    fun passivePathNamesNoActiveQueueCall() {
        val passivePath =
            SourceRoots.kotlinFiles().filter { file ->
                val path = SourceRoots.packageRelativePath(file)
                (path.startsWith("scanner/PassiveAiScanner") && path.endsWith(".kt")) ||
                    path == "scanner/AiPassiveScanCheck.kt" ||
                    path == "scanner/SuggestedTargetList.kt"
            }
        val names = passivePath.map { SourceRoots.packageRelativePath(it) }
        assertTrue(passivePath.size >= MIN_PASSIVE_PATH_FILES, "walked only ${passivePath.size} passive-path files: $names")
        assertTrue("scanner/SuggestedTargetList.kt" in names, "the walk missed SuggestedTargetList.kt: $names")
        val hits =
            passivePath.flatMap { file ->
                val path = SourceRoots.packageRelativePath(file)
                file.readLines(Charsets.UTF_8).flatMapIndexed { index, line ->
                    ACTIVE_QUEUE_TOKENS.filter { it in line }.map { "$path:${index + 1}: $it" }
                }
            }
        assertEquals(emptyList<String>(), hits, "passive-path files must not name the active scanner or its queue calls")
    }

    @Test
    fun storeClasspathResolvesTheCoreDefaults() {
        val profile = resolveFlavorProfile()
        val policy = resolveAiAccessPolicy()
        assertTrue(profile is StoreFlavorProfile, "got ${profile.javaClass.name}")
        assertTrue(policy is StoreAiAccessPolicy, "got ${policy.javaClass.name}")
    }

    @Test
    fun describeToolsListsExactlyTheEightNativeIds() {
        val preamble = McpToolExecutor.describeTools(storeContext(), includeSchemas = false)
        val listed =
            preamble
                .lines()
                .filter { it.startsWith("- ") }
                .map { it.removePrefix("- ").substringBefore(":") }
        assertEquals(NATIVE_IDS, listed.toSet(), "describeTools must list exactly the native tools:\n$preamble")
        assertEquals(NATIVE_IDS.size, listed.size)
        assertFalse(GENERIC_ID in preamble, "no generic tool may be described in the store build")
    }

    @Test
    fun genericNamesAreUnknownAndFailClosedInTheStoreBuild() {
        assertEquals("history", McpToolExecutor.canonicalToolId("history"), "the generic alias table is absent")
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor(GENERIC_ID))
        assertEquals(SecTier.CONFIRM_EACH, ToolApprovalGate.tierFor("history"))

        val result = McpToolExecutor.executeToolResult(GENERIC_ID, "{}", storeContext())
        assertEquals(true, result.isError, "a generic tool name must be rejected in the store build")
        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text.orEmpty() }
        assertTrue(text.startsWith("Unknown tool: $GENERIC_ID"), "got: $text")
    }

    private fun storeContext(): McpToolContext {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        return McpToolContext(
            api = api,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = false,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(4),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = 8192,
        )
    }

    private companion object {
        /** scanner/PassiveAiScanner*.kt (8 today), AiPassiveScanCheck.kt and SuggestedTargetList.kt. */
        const val MIN_PASSIVE_PATH_FILES = 10

        /** The active scanner's class name and its queue calls (Phase 32 SC1). */
        val ACTIVE_QUEUE_TOKENS = listOf("ActiveAiScanner", "queueTarget(", "tryQueueTarget(", "queueSuggested(")

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

        /** The six core HTTP factories, sorted by class name as [Plugins.load] returns them. */
        val STORE_FACTORIES =
            listOf(
                "com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory",
                "com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory",
                "com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory",
                "com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory",
                "com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory",
                "com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory",
            )

        val STORE_BACKEND_IDS =
            listOf("anthropic", "burp-ai", "lmstudio", "nvidia-nim", "ollama", "openai-compatible", "perplexity")

        /** The drop-in loader's tokens, spelled only here: comments in src/main must not spell them either. */
        const val DROP_IN_DIR = ".burp-ai-agent/backends"
        const val URL_CLASS_LOADER = "URLClassLoader"
        val DROP_IN_TOKENS = listOf(DROP_IN_DIR, URL_CLASS_LOADER)

        /** A generic tool of the full build (GenericHistoryTools), and the target of the "history" alias there. */
        const val GENERIC_ID = "proxy_http_history"
    }
}
