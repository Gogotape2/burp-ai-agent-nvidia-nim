package com.six2dez.burp.aiagent.full

import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.ToolApprovalGate
import com.six2dez.burp.aiagent.mcp.tools.GenericToolProvider
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.spi.AiAccessPolicy
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.ToolProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
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
    fun genericToolProviderIsTheOneToolProvider() {
        val providers = Plugins.load(ToolProvider::class.java)
        assertEquals(listOf(GenericToolProvider::class.java.name), providers.map { it.javaClass.name })
        assertEquals(FULL_TOOL_COUNT - NATIVE_IDS.size, providers.single().handlers().size, "generic tool count")
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

        val EXPECTED_SPI_TYPES =
            setOf(
                "com.six2dez.burp.aiagent.backends.AiBackendFactory",
                "com.six2dez.burp.aiagent.spi.AiAccessPolicy",
                "com.six2dez.burp.aiagent.spi.BackendModelHint",
                "com.six2dez.burp.aiagent.spi.FlavorProfile",
                "com.six2dez.burp.aiagent.spi.SettingsContribution",
                "com.six2dez.burp.aiagent.spi.ToolProvider",
            )
    }
}
