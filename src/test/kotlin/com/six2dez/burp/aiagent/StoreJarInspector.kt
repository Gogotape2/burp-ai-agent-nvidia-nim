package com.six2dez.burp.aiagent

import java.io.File
import java.util.zip.ZipFile

/**
 * Phase 30 / CI-01 (ADR-18: the store flavor is "checked by content, not by intent"): the rules that decide
 * whether the BApp Store JAR holds content that belongs to the GitHub full build only.
 *
 * It automates the manual 29-17 check (an `unzip -Z1 | grep` over the store JAR) and is a strict superset of
 * that check. The forbidden set has three layers:
 * - **A, derived**: every file compiled from `src/full` ([fullOnlyEntries]). Self-maintaining: a class added
 *   to `src/full` is covered without touching this file.
 * - **B, denylist**: full-only packages, full-only class names and bundled libraries the store build must not
 *   ship. It catches code planted in `src/main` under a full-only name, which layer A cannot see.
 * - **C, services**: the only `com.six2dez` services file allowed is the AiBackendFactory one, and it must
 *   list exactly the six HTTP backend factories.
 *
 * The functions are pure over a list of entry names, so `StoreJarInspectorTest` proves every rule red on a
 * synthetic JAR in plain `test`, and StoreJarContentTest applies them to the real JAR in the
 * `storeJarContentTest` Gradle task. Fix a reported entry in the packaging or by moving the code to
 * `src/full`; never by relaxing a rule.
 */
internal object StoreJarInspector {
    /** System property carrying the absolute path of the JAR bappJar writes. */
    const val STORE_JAR_PROPERTY = "burp.aiagent.storeJar"

    /** System property carrying the src/full class directories, joined with [File.pathSeparator]. */
    const val FULL_CLASS_DIRS_PROPERTY = "burp.aiagent.fullClassDirs"

    /** System property carrying the absolute path of the JAR fullJar writes (Phase 31 / NET-01, OkHttp check only). */
    const val FULL_JAR_PROPERTY = "burp.aiagent.fullJar"

    /** OkHttp, Okio and MockWebServer path prefixes; neither JAR may hold an entry under them (Phase 31 / NET-01). */
    val OKHTTP_PREFIXES: List<String> = emptyList()

    /** The entries of [entries] under an [OKHTTP_PREFIXES] prefix, sorted. */
    fun okHttpEntries(entries: List<String>): List<String> = emptyList()

    const val FACTORY_SERVICES_ENTRY = "META-INF/services/com.six2dez.burp.aiagent.backends.AiBackendFactory"

    /** The six HTTP backend factories the store JAR registers (the 29-17 baseline). A new HTTP backend updates this set. */
    val HTTP_BACKEND_FACTORIES: Set<String> =
        linkedSetOf(
            "com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackendFactory",
            "com.six2dez.burp.aiagent.backends.nvidia.NvidiaNimBackendFactory",
            "com.six2dez.burp.aiagent.backends.perplexity.PerplexityBackendFactory",
            "com.six2dez.burp.aiagent.backends.ollama.OllamaBackendFactory",
            "com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackendFactory",
            "com.six2dez.burp.aiagent.backends.anthropic.AnthropicBackendFactory",
        )

    /** Layer B1: packages that belong to the full build. A prefix, so it also matches an empty directory entry. */
    private val FULL_ONLY_PACKAGES =
        listOf(
            "com/six2dez/burp/aiagent/full/",
            "com/six2dez/burp/aiagent/backends/cli/",
            "com/six2dez/burp/aiagent/mcp/external/",
            "com/six2dez/burp/aiagent/alerts/",
        )

    private const val OWN_ENTRY_ROOT = "com/six2dez/"

    /** Layer B2: simple-name prefixes of full-only classes (generic MCP tools, external MCP client, auto-queue, ...). */
    private val FULL_ONLY_NAME_PREFIXES =
        listOf(
            "Generic",
            "ExternalMcp",
            "ExternalServers",
            "ExternalTool",
            "AutoQueue",
            "Alerting",
            "McpScopeFilter",
            "ScannerTaskRegistry",
            "CollaboratorRegistry",
            "McpToolHelpersKt",
            "McpToolModelsKt",
        )

    private const val CLI_BACKEND_MARKER = "CliBackend"

    /**
     * Layer B3: libraries the store build does not ship. The whole Ktor client tree (the store JAR has no entry
     * there), the Ktor server CIO engine, Ktor TLS and the MCP SDK client. `io/ktor/network/{selector,sockets,util}`
     * stay allowed: the Netty-based store MCP server uses them.
     */
    private val BUNDLED_LIBRARY_PREFIXES =
        listOf(
            "io/ktor/client/",
            "io/ktor/server/cio/",
            "io/ktor/network/tls/",
            "io/modelcontextprotocol/kotlin/sdk/client/",
            "META-INF/ktor-client-",
            "META-INF/ktor-network-tls",
        )

    private const val OWN_SERVICES_PREFIX = "META-INF/services/com.six2dez."
    private const val KTOR_CLIENT_SERVICES_PREFIX = "META-INF/services/io.ktor.client."

    /** One rule per forbidden category. When an entry matches several, the first in declaration order wins. */
    enum class Rule(
        val reason: String,
    ) {
        DERIVED_FULL_CLASS("compiled from src/full; the store JAR packages src/main only"),
        FULL_ONLY_PACKAGE("inside a full-only package (full/, backends/cli/, mcp/external/, alerts/)"),
        FULL_ONLY_NAME("a full-only class name (generic MCP tools, external MCP client, auto-queue, CLI backend)"),
        BUNDLED_LIBRARY("a library the store build does not ship (Ktor client or CIO, Ktor TLS, MCP SDK client)"),
        SERVICES_FILE("a plug-in services file; the store JAR registers only the HTTP backend factories"),
        FACTORY_LIST("the AiBackendFactory services file must list exactly the six HTTP backend factories"),
    }

    data class Violation(
        val entry: String,
        val rule: Rule,
    )

    /**
     * Applies every rule to [entries] (ZIP entry names, '/'-separated, directory entries included).
     * [serviceText] returns the UTF-8 text of a services entry, or null when the JAR does not hold it;
     * [fullOnly] is the derived set from [fullOnlyEntries]. Returns one violation per entry, sorted by entry,
     * so the same JAR always produces the same report.
     */
    fun inspect(
        entries: List<String>,
        serviceText: (String) -> String?,
        fullOnly: Set<String>,
    ): List<Violation> {
        val perEntry = entries.mapNotNull { entry -> entryRule(entry, fullOnly)?.let { Violation(entry, it) } }
        val factoryList = factoryListViolations(serviceText(FACTORY_SERVICES_ENTRY))
        return (perEntry + factoryList).distinctBy { it.entry }.sortedBy { it.entry }
    }

    /** Opens [jar] and applies [inspect] to its entries; services files are read as UTF-8. */
    fun inspect(
        jar: File,
        fullOnly: Set<String>,
    ): List<Violation> =
        ZipFile(jar).use { zip ->
            val names = zip.names()
            val text: (String) -> String? = { name ->
                zip.getEntry(name)?.let { entry -> zip.getInputStream(entry).use { it.readBytes().toString(Charsets.UTF_8) } }
            }
            inspect(names, text, fullOnly)
        }

    fun entryNames(jar: File): List<String> = ZipFile(jar).use { it.names() }

    private fun ZipFile.names(): List<String> = entries().toList().map { it.name }

    /**
     * Every file under [classDirs] as a '/'-relative path, the form of a ZIP entry name. A missing directory is
     * ignored. `invariantSeparatorsPath` matters: on Windows a plain relative path is backslash-separated, so
     * nothing would ever equal an entry name and layer A would pass vacuously (RESEARCH Pitfall 6).
     */
    fun fullOnlyEntries(classDirs: List<File>): Set<String> =
        classDirs
            .filter { it.isDirectory }
            .flatMap { dir ->
                dir
                    .walkTopDown()
                    .filter { it.isFile }
                    .map { it.relativeTo(dir).invariantSeparatorsPath }
                    .toList()
            }.toSet()

    /** The failure message: what went wrong, how to fix it, then one line per offending entry. */
    fun report(
        jar: File,
        violations: List<Violation>,
    ): String =
        "The BApp Store JAR contains full-only or CLI content (CI-01): ${jar.absolutePath}\n" +
            "Fix the packaging in bappJar or move the code to src/full; never relax a rule or allowlist an entry.\n" +
            violations.joinToString("\n") { "  ${it.entry}  (${it.rule}: ${it.rule.reason})" }

    private fun entryRule(
        entry: String,
        fullOnly: Set<String>,
    ): Rule? =
        when {
            entry in fullOnly -> Rule.DERIVED_FULL_CLASS
            FULL_ONLY_PACKAGES.any { entry.startsWith(it) } -> Rule.FULL_ONLY_PACKAGE
            isFullOnlyName(entry) -> Rule.FULL_ONLY_NAME
            BUNDLED_LIBRARY_PREFIXES.any { entry.startsWith(it) } -> Rule.BUNDLED_LIBRARY
            isPluginServicesFile(entry) -> Rule.SERVICES_FILE
            else -> null
        }

    /**
     * Layer B2: the last path segment of an entry under `com/six2dez/`, matched case-sensitively. Never a bare
     * `Client` or case-insensitive `cli` rule: the store legitimately ships McpTakeoverClient and dozens of MCP
     * SDK `Client*` model classes, and 123 store entries contain `cli` in some case (RESEARCH Pitfall 4).
     */
    private fun isFullOnlyName(entry: String): Boolean {
        if (!entry.startsWith(OWN_ENTRY_ROOT)) return false
        val name = entry.removeSuffix("/").substringAfterLast('/')
        return FULL_ONLY_NAME_PREFIXES.any { name.startsWith(it) } || name.contains(CLI_BACKEND_MARKER)
    }

    /**
     * Layer C1: the AiBackendFactory file is the only `com.six2dez` services file the store JAR may carry, and no
     * Ktor client engine container may be registered. Third-party services files are not pinned: an exact pin
     * would fail on every Dependabot bump. The bare `META-INF/services/` directory entry is allowed.
     */
    private fun isPluginServicesFile(entry: String): Boolean {
        val ownPlugin = entry.startsWith(OWN_SERVICES_PREFIX) && entry != FACTORY_SERVICES_ENTRY
        return ownPlugin || entry.startsWith(KTOR_CLIENT_SERVICES_PREFIX)
    }

    /**
     * Layer C2. Lines are trimmed; blank and `#` lines are skipped, so CRLF endings, comments and a missing
     * final newline (the merged store file has none) do not matter. Every unexpected line and every absent
     * expected factory is reported; a missing services file reports all six as missing.
     */
    private fun factoryListViolations(text: String?): List<Violation> {
        val lines =
            text
                .orEmpty()
                .lines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
        val unexpected = lines.filter { it !in HTTP_BACKEND_FACTORIES }.map { "$FACTORY_SERVICES_ENTRY: $it" }
        val missing = HTTP_BACKEND_FACTORIES.filter { it !in lines }.map { "$FACTORY_SERVICES_ENTRY: missing $it" }
        return (unexpected + missing).map { Violation(it, Rule.FACTORY_LIST) }
    }
}
