package com.six2dez.burp.aiagent

import com.six2dez.burp.aiagent.StoreJarInspector.FACTORY_SERVICES_ENTRY
import com.six2dez.burp.aiagent.StoreJarInspector.HTTP_BACKEND_FACTORIES
import com.six2dez.burp.aiagent.StoreJarInspector.Rule
import com.six2dez.burp.aiagent.StoreJarInspector.Violation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Phase 30 / CI-01: fail-first proof of every [StoreJarInspector] rule, on synthetic JARs.
 *
 * StoreJarContentTest applies the rules to the real store JAR, which is clean, so a rule that stopped
 * matching would leave it green over a JAR that still leaked. This class plants one entry per category
 * (generic MCP tools, external MCP client, Ktor CIO / client, MCP SDK client, auto-queue, CLI backend,
 * plug-in services file, CLI factory line) into a clean baseline and asserts the exact violation list, and
 * pins the legitimate store look-alikes that must never be reported. It also proves the rules are a superset
 * of the manual 29-17 check: every alternative of its regex is reported. It runs in plain `test`, on all
 * three operating systems, in every PR (the shape of FlavorBranchGuardTest's synthetic-line proof).
 */
class StoreJarInspectorTest {
    @TempDir
    lateinit var dir: File

    private var jarCount = 0

    @Test
    fun cleanBaselineReportsNothing() {
        assertEquals(emptyList<Violation>(), inspect(BASELINE, emptySet()))
    }

    @Test
    fun aFileCompiledFromSrcFullIsReportedThroughTheDerivedSet() {
        val planted = "com/six2dez/burp/aiagent/mcp/tools/Base64Encode.class"
        assertEquals(listOf(Violation(planted, Rule.DERIVED_FULL_CLASS)), inspect(BASELINE + (planted to ""), setOf(planted)))
        // Its name matches no denylist entry: only the derived layer catches it.
        assertEquals(emptyList<Violation>(), inspect(BASELINE + (planted to ""), emptySet()))
    }

    @Test
    fun fullOnlyPackagesAreReported() {
        assertEachReported(
            Rule.FULL_ONLY_PACKAGE,
            "com/six2dez/burp/aiagent/full/autoqueue/AutoQueuePlugin.class",
            "com/six2dez/burp/aiagent/mcp/external/ExternalMcpClientManager.class",
            "com/six2dez/burp/aiagent/alerts/Alerting.class",
            "com/six2dez/burp/aiagent/backends/cli/",
        )
    }

    @Test
    fun fullOnlyClassNamesAreReported() {
        assertEachReported(
            Rule.FULL_ONLY_NAME,
            "com/six2dez/burp/aiagent/mcp/tools/GenericHttpRequestTool.class",
            "com/six2dez/burp/aiagent/ui/ExternalServersPanel.class",
            "com/six2dez/burp/aiagent/backends/codex/CodexCliBackend.class",
            "com/six2dez/burp/aiagent/scanner/ScannerTaskRegistry.class",
            "com/six2dez/burp/aiagent/mcp/McpScopeFilter.class",
            "com/six2dez/burp/aiagent/scanner/CollaboratorRegistry.class",
            "com/six2dez/burp/aiagent/mcp/tools/McpToolHelpersKt.class",
            "com/six2dez/burp/aiagent/mcp/tools/McpToolModelsKt.class",
        )
    }

    @Test
    fun bundledLibrariesTheStoreDoesNotShipAreReported() {
        assertEachReported(
            Rule.BUNDLED_LIBRARY,
            "io/ktor/client/engine/cio/CIOEngine.class",
            "io/ktor/client/HttpClient.class",
            "io/ktor/server/cio/CIOApplicationEngine.class",
            "io/ktor/network/tls/TLSConfig.class",
            "io/modelcontextprotocol/kotlin/sdk/client/Client.class",
            "META-INF/ktor-client-core.kotlin_module",
        )
    }

    @Test
    fun pluginServicesFilesAreReported() {
        val spi = listOf("ToolProvider", "SettingsContribution", "ExtensionPlugin", "BackendModelHint", "FlavorProfile", "AiAccessPolicy")
        assertEachReported(
            Rule.SERVICES_FILE,
            *(spi.map { "META-INF/services/com.six2dez.burp.aiagent.spi.$it" } + "META-INF/services/io.ktor.client.HttpClientEngineContainer")
                .toTypedArray(),
        )
    }

    @Test
    fun aCliFactoryLineIsReportedNamingTheLine() {
        val line = "com.six2dez.burp.aiagent.backends.cli.CodexCliBackendFactory"
        assertEquals(
            listOf(Violation("$FACTORY_SERVICES_ENTRY: $line", Rule.FACTORY_LIST)),
            inspect(BASELINE + (FACTORY_SERVICES_ENTRY to (HTTP_BACKEND_FACTORIES + line).joinToString("\n")), emptySet()),
        )
    }

    @Test
    fun aMissingHttpFactoryIsReportedNamingTheFactory() {
        val ollama = "com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory"
        assertEquals(
            listOf(Violation("$FACTORY_SERVICES_ENTRY: missing $ollama", Rule.FACTORY_LIST)),
            inspect(BASELINE + (FACTORY_SERVICES_ENTRY to (HTTP_BACKEND_FACTORIES - ollama).joinToString("\n")), emptySet()),
        )
    }

    @Test
    fun everyAlternativeOfThe2917ManualCheckIsReported() {
        // 29-17-PLAN.md: the `unzip -Z1 | grep -E` regex over the store JAR, one alternative per row.
        val alternatives =
            listOf(
                "com/six2dez/burp/aiagent/full/FullFlavorProfile.class" to Rule.FULL_ONLY_PACKAGE, // aiagent/full/
                "com/six2dez/burp/aiagent/backends/cli/CliBackend.class" to Rule.FULL_ONLY_PACKAGE, // backends/cli/
                "com/six2dez/burp/aiagent/mcp/external/ExternalMcpConfig.class" to Rule.FULL_ONLY_PACKAGE, // mcp/external/
                "com/six2dez/burp/aiagent/ui/ExternalServersPanel\$1.class" to Rule.FULL_ONLY_NAME, // ExternalServersPanel
                "com/six2dez/burp/aiagent/mcp/tools/GenericRepeaterTool.class" to Rule.FULL_ONLY_NAME, // mcp/tools/Generic
                "com/six2dez/burp/aiagent/mcp/tools/McpToolHelpersKt.class" to Rule.FULL_ONLY_NAME, // McpToolHelpersKt
                "com/six2dez/burp/aiagent/mcp/tools/McpToolModelsKt.class" to Rule.FULL_ONLY_NAME, // McpToolModelsKt
                "com/six2dez/burp/aiagent/mcp/McpScopeFilter\$Companion.class" to Rule.FULL_ONLY_NAME, // McpScopeFilter
                "com/six2dez/burp/aiagent/scanner/ScannerTaskRegistry.class" to Rule.FULL_ONLY_NAME, // ScannerTaskRegistry
                "com/six2dez/burp/aiagent/scanner/CollaboratorRegistry.class" to Rule.FULL_ONLY_NAME, // CollaboratorRegistry
                "com/six2dez/burp/aiagent/alerts/AlertSink.class" to Rule.FULL_ONLY_PACKAGE, // alerts/
                "io/ktor/client/engine/cio/CIO.class" to Rule.BUNDLED_LIBRARY, // io/ktor/client/engine/cio/
                "io/ktor/server/cio/CIO.class" to Rule.BUNDLED_LIBRARY, // io/ktor/server/cio/
                "io/modelcontextprotocol/kotlin/sdk/client/StdioClientTransport.class" to Rule.BUNDLED_LIBRARY, // kotlin/sdk/client/
            ) +
                listOf("ToolProvider", "SettingsContribution", "ExtensionPlugin", "BackendModelHint", "FlavorProfile", "AiAccessPolicy")
                    .map { "META-INF/services/com.six2dez.burp.aiagent.spi.$it" to Rule.SERVICES_FILE } // spi\.(...)$
        alternatives.forEach { (planted, rule) ->
            assertEquals(
                listOf(Violation(planted, rule)),
                inspect(BASELINE + (planted to ""), emptySet()),
                "the 29-17 alternative carried by $planted is not reported as $rule",
            )
        }
        // 29-17's second check: no line of the AiBackendFactory services file contains `cli`.
        val cliLine = "com.six2dez.burp.aiagent.backends.cli.GeminiCliBackendFactory"
        assertEquals(
            listOf(Violation("$FACTORY_SERVICES_ENTRY: $cliLine", Rule.FACTORY_LIST)),
            inspect(BASELINE + (FACTORY_SERVICES_ENTRY to (HTTP_BACKEND_FACTORIES + cliLine).joinToString("\n")), emptySet()),
        )
    }

    @Test
    fun legitimateStoreLookAlikesAreNeverReported() {
        listOf(
            "com/six2dez/burp/aiagent/mcp/McpTakeoverClient.class",
            "com/six2dez/burp/aiagent/mcp/McpSupervisor\$takeoverClient\$1.class",
            "io/modelcontextprotocol/kotlin/sdk/ClientCapabilities.class",
            "com/six2dez/burp/aiagent/mcp/tools/ResponsePreprocessorSettings.class",
            "io/ktor/network/sockets/ABoundSocket.class",
            "io/ktor/network/selector/SelectorManager.class",
            "META-INF/services/io.ktor.server.config.ConfigLoader",
            "META-INF/services/com.fasterxml.jackson.core.JsonFactory",
        ).forEach { entry ->
            assertEquals(emptyList<Violation>(), inspect(BASELINE + (entry to ""), emptySet()), "$entry is legitimate store content")
        }
    }

    @Test
    fun crlfEndingsACommentAndNoTrailingNewlineAreAccepted() {
        val text = "# HTTP backends only\r\n" + HTTP_BACKEND_FACTORIES.joinToString("\r\n")
        assertEquals(emptyList<Violation>(), inspect(BASELINE + (FACTORY_SERVICES_ENTRY to text), emptySet()))
    }

    @Test
    fun anEntryMatchingSeveralRulesIsReportedOnceUnderTheFirstRule() {
        // Matches both the backends/cli/ package and the CliBackend name.
        val planted = "com/six2dez/burp/aiagent/backends/cli/ClaudeCliBackendFactory.class"
        assertEquals(listOf(Violation(planted, Rule.FULL_ONLY_PACKAGE)), inspect(BASELINE + (planted to ""), emptySet()))
        assertEquals(listOf(Violation(planted, Rule.DERIVED_FULL_CLASS)), inspect(BASELINE + (planted to ""), setOf(planted)))
    }

    @Test
    fun inspectingTheSameJarTwiceReturnsTheSameSortedList() {
        val entries =
            BASELINE +
                listOf(
                    "io/ktor/server/cio/CIO.class" to "",
                    "com/six2dez/burp/aiagent/alerts/Alerting.class" to "",
                    "META-INF/services/com.six2dez.burp.aiagent.spi.ToolProvider" to "",
                )
        val jar = jarOf(entries)
        val first = StoreJarInspector.inspect(jar, emptySet())
        val second = StoreJarInspector.inspect(jar, emptySet())
        assertEquals(first, second)
        assertEquals(first.sortedBy { it.entry }, first, "violations must be sorted by entry")
        assertEquals(3, first.size)
    }

    @Test
    fun fullOnlyEntriesAreSlashSeparatedAndAMissingDirectoryIsIgnored() {
        val classes = File(dir, "classes")
        File(classes, "a/b").mkdirs()
        File(classes, "a/b/C.class").writeText("")
        File(classes, "META-INF").mkdirs()
        File(classes, "META-INF/x.kotlin_module").writeText("")
        assertEquals(
            setOf("a/b/C.class", "META-INF/x.kotlin_module"),
            StoreJarInspector.fullOnlyEntries(listOf(classes, File(dir, "does-not-exist"))),
        )
    }

    private fun assertEachReported(
        rule: Rule,
        vararg planted: String,
    ) {
        planted.forEach { entry ->
            assertEquals(
                listOf(Violation(entry, rule)),
                inspect(BASELINE + (entry to ""), emptySet()),
                "$entry planted into a clean JAR is not reported as $rule",
            )
        }
    }

    private fun inspect(
        entries: Map<String, String>,
        fullOnly: Set<String>,
    ): List<Violation> = StoreJarInspector.inspect(jarOf(entries), fullOnly)

    /** Writes [entries] (name to UTF-8 text; a name ending in '/' is a directory entry) into a new JAR. */
    private fun jarOf(entries: Map<String, String>): File {
        val file = File(dir, "synthetic-${jarCount++}.jar")
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            entries.forEach { (name, text) ->
                zip.putNextEntry(ZipEntry(name))
                if (!name.endsWith("/")) zip.write(text.toByteArray(Charsets.UTF_8))
                zip.closeEntry()
            }
        }
        return file
    }

    private companion object {
        val BASELINE: Map<String, String> =
            linkedMapOf(
                "com/six2dez/burp/aiagent/BurpAiAgentExtension.class" to "",
                "com/six2dez/burp/aiagent/backends/ollama/OllamaBackendFactory.class" to "",
                "META-INF/services/" to "",
                FACTORY_SERVICES_ENTRY to HTTP_BACKEND_FACTORIES.joinToString("\n"),
                "META-INF/services/com.fasterxml.jackson.core.JsonFactory" to "com.fasterxml.jackson.core.JsonFactory",
            )
    }
}
