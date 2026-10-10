package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 29 (DEAD-01, NET-02, D-05): code deleted as dead stays deleted, in BOTH production roots.
 *
 * PortSwigger's reviewer reads `src/full` as well as `src/main`, so dead code that is moved into the
 * full-only source set instead of being deleted is still dead code in the review. This guard walks
 * every production root through [SourceRoots.kotlinFiles] and fails, naming `file:line`, when the
 * identifier of a deleted symbol appears anywhere, comments and KDoc included: "nothing references
 * it" covers prose too, because a comment naming a deleted symbol is a pointer to code that no longer
 * exists.
 *
 * Matching is on identifier boundaries, so `AlertingPolicy` or `toLowerSnakeCaseName` would not trip
 * the `Alerting` / `toLowerSnakeCase` entries. Later plans extend [DELETED_SYMBOLS] and [DELETED_PATHS]
 * by appending entries; each entry names the requirement that deleted it.
 */
class DeadCodeGuardTest {
    @Test
    fun noDeletedSymbolIsNamedInEitherProductionRoot() {
        val hits =
            SourceRoots.kotlinFiles().flatMap { file ->
                findDeletedSymbols(SourceRoots.relativePath(file), file.readLines())
            }
        assertTrue(
            hits.isEmpty(),
            "Deleted code is named again in a production root. Delete the reference; do not move the " +
                "code into src/full instead (D-05: the reviewer reads both roots).\n" +
                hits.joinToString("\n") { "  ${it.location}: `${it.symbol.identifier}` (${it.symbol.reason}) -> ${it.line.trim()}" },
        )
    }

    @Test
    fun noDeletedPathExistsInEitherProductionRoot() {
        val present =
            DELETED_PATHS.flatMap { deleted ->
                SourceRoots.PRODUCTION
                    .map { root -> SourceRoots.root(root).resolve(deleted.path) }
                    .filter { it.exists() }
                    .map { "${it.path} (${deleted.reason})" }
            }
        assertTrue(
            present.isEmpty(),
            "A deleted file or package is back in a production root: $present",
        )
    }

    @Test
    fun theMatcherReportsAForbiddenIdentifierOnASyntheticLine() {
        // Fail-first proof: if the matcher stopped matching, the whole-tree guard above would pass
        // over a tree that still holds the deleted code.
        DELETED_SYMBOLS.forEach { symbol ->
            val line = "    val x = ${symbol.identifier}.call() // synthetic"
            val hits = findDeletedSymbols("synthetic/Fixture.kt", listOf("package x", line))
            assertEquals(
                listOf("synthetic/Fixture.kt:2"),
                hits.map { it.location },
                "the matcher did not report `${symbol.identifier}` on a synthetic line that names it",
            )
        }
        val commentHits = findDeletedSymbols("synthetic/Fixture.kt", listOf(" * see Alerting for the old webhook"))
        assertEquals(1, commentHits.size, "a deleted identifier in a KDoc line must be reported too")
    }

    @Test
    fun theMatcherRespectsIdentifierBoundaries() {
        val lines =
            listOf(
                "val policy = AlertingPolicy()",
                "fun toLowerSnakeCaseName() = 1",
                "val myMcpToolLegacyNote = 2",
                "import com.six2dez.burp.aiagent.alertsv2.Thing",
                "val mcpToolCount = 3",
                "private class NonInteractiveCliConnection(",
                "if (recheckHealth) requestHealthCheck()",
                "val autoRestartLabel = 4",
            )
        assertEquals(
            emptyList<String>(),
            findDeletedSymbols("synthetic/Fixture.kt", lines).map { "${it.location} ${it.symbol.identifier}" },
            "identifiers that merely CONTAIN a deleted name must not be reported",
        )
    }

    @Test
    fun everyEntryStatesWhichRequirementDeletedIt() {
        (DELETED_SYMBOLS.map { it.identifier to it.reason } + DELETED_PATHS.map { it.path to it.reason }).forEach { (name, reason) ->
            assertTrue(
                REQUIREMENT_ID.containsMatchIn(reason),
                "the entry for `$name` does not name the requirement that deleted it: \"$reason\"",
            )
        }
    }

    private data class DeletedSymbol(
        val identifier: String,
        val reason: String,
    ) {
        val pattern: Regex = Regex("(?<![A-Za-z0-9_])" + Regex.escape(identifier) + "(?![A-Za-z0-9_])")
    }

    private data class DeletedPath(
        val path: String,
        val reason: String,
    )

    private data class Hit(
        val location: String,
        val symbol: DeletedSymbol,
        val line: String,
    )

    private fun findDeletedSymbols(
        relativePath: String,
        lines: List<String>,
    ): List<Hit> =
        lines.withIndex().flatMap { (index, line) ->
            DELETED_SYMBOLS.filter { it.pattern.containsMatchIn(line) }.map { Hit("$relativePath:${index + 1}", it, line) }
        }

    private companion object {
        val REQUIREMENT_ID = Regex("""\b[A-Z]+-\d{2}\b""")

        /** Append-only: plan 29-05 adds the second half of the dead code here. */
        val DELETED_SYMBOLS =
            listOf(
                DeletedSymbol("McpToolLegacy", "DEAD-01: the legacy MCP registrar file, deleted by plan 29-04"),
                DeletedSymbol("registerToolsLegacy", "DEAD-01: the legacy MCP registrar, deleted by plan 29-04"),
                DeletedSymbol("mcpTool", "DEAD-01: Server.mcpTool overloads, only called by the legacy registrar"),
                DeletedSymbol("mcpPaginatedTool", "DEAD-01: Server.mcpPaginatedTool, only called by the legacy registrar"),
                DeletedSymbol("toLowerSnakeCase", "DEAD-01: tool-name helper, only called by the deleted Server.mcpTool"),
                DeletedSymbol("Alerting", "NET-02: unwired webhook object with its own OkHttp client, deleted by plan 29-04"),
                DeletedSymbol("com.six2dez.burp.aiagent.alerts", "NET-02: the alerts package, which held only Alerting"),
                DeletedSymbol("CliConnection", "DEAD-01 (plan 29-05): the interactive CLI connection behind the always-true embedded switch"),
                DeletedSymbol("buildPtyCommand", "DEAD-01 (plan 29-05): the PTY wrapper that joined escaped argv into one shell string"),
                DeletedSymbol("shellEscape", "DEAD-01 (plan 29-05): shell quoting for the deleted PTY wrapper"),
                DeletedSymbol("isUnixLike", "DEAD-01 (plan 29-05): the PTY wrapper's OS check"),
                DeletedSymbol("usePty", "DEAD-01 (plan 29-05): the PTY switch in CliBackend.launch"),
                DeletedSymbol("embeddedMode", "DEAD-01 (plan 29-05): BackendLaunchConfig switch that was always true"),
                DeletedSymbol("DiagnosableConnection", "DEAD-01 (plan 29-05): implemented only by the deleted CliConnection"),
                DeletedSymbol("monitorExec", "DEAD-01 (plan 29-05): the auto-restart health monitor's scheduler"),
                DeletedSymbol("checkHealth", "DEAD-01 (plan 29-05): the auto-restart health monitor's recurring task"),
                DeletedSymbol("buildExitDetail", "DEAD-01 (plan 29-05): the monitor's exit-detail reader of DiagnosableConnection"),
                DeletedSymbol("autoRestartSuppressed", "DEAD-01 (plan 29-05): auto-restart monitor counter"),
                DeletedSymbol("immediateCrashCount", "DEAD-01 (plan 29-05): auto-restart monitor counter"),
                DeletedSymbol("lastRestartAt", "DEAD-01 (plan 29-05): auto-restart monitor counter"),
                DeletedSymbol("HEALTH_CHECK_INTERVAL_MS", "DEAD-01 (plan 29-05): the auto-restart monitor's interval"),
                DeletedSymbol("workerPool", "DEAD-01 (plan 29-05): App's fixed pool, whose only work was the auto-restart submit"),
                DeletedSymbol("workerPoolThreadFactory", "DEAD-01 (plan 29-05): thread factory of the deleted worker pool"),
                DeletedSymbol("MAX_WORKER_THREADS", "DEAD-01 (plan 29-05): ceiling of the deleted worker pool"),
                DeletedSymbol("autoRestart", "DEAD-01 (plan 29-05): the auto-restart setting and its Privacy tab row"),
                DeletedSymbol("KEY_AUTORESTART", "DEAD-01 (plan 29-05): preference key constant of the removed setting"),
                DeletedSymbol("agent.autorestart", "DEAD-01 (plan 29-05): the stored key is left in preferences, never read or written"),
            )

        /** Root-relative paths that must exist in neither production root. Append-only. */
        val DELETED_PATHS =
            listOf(
                DeletedPath("${SourceRoots.PACKAGE_DIR}/mcp/tools/McpToolLegacy.kt", "DEAD-01: plan 29-04"),
                DeletedPath("${SourceRoots.PACKAGE_DIR}/alerts", "NET-02: plan 29-04"),
            )
    }
}
