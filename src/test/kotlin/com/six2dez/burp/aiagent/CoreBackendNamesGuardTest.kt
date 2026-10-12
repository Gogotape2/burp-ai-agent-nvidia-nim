package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 29 / D-06, D-07, threat T-29-27 — the core (`src/main/kotlin`, the only input of the BApp Store
 * JAR) names no CLI backend. Each CLI id, each per-CLI setting, the `backends.cli` package and the
 * external terminal launcher live only in `src/full`, so the store JAR has no CLI type, field, key
 * access or UI and cannot spawn a terminal from its settings window.
 *
 * Comments count: a core KDoc that names a CLI id is the first step back to core code that branches on
 * it, and the store reviewers read the source.
 *
 * Two generic launch-spec members are allowed (OQ5): `BackendLaunchConfig.cliTimeoutSeconds` and
 * `BackendLaunchConfig.cliSessionId` describe any backend that runs a local process and carry no CLI
 * id, so a drop-in backend JAR can use them. `cliSessionId` matches no pattern; the allowed
 * `cliTimeoutSeconds` lines are the member's declaration and `PromptBundle`'s copy of it (the audit
 * bundle records the launch configuration a prompt was sent with). Any other `cliTimeoutSeconds` (the
 * deleted `AgentSettings` field) fails.
 */
class CoreBackendNamesGuardTest {
    @Test
    fun coreSourceNamesNoCliBackendSettingPackageOrLauncher() {
        val mainRoot = SourceRoots.root(SourceRoots.MAIN)
        val files = mainRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(files.size > MIN_EXPECTED_FILES, "the walk of ${SourceRoots.MAIN} found only ${files.size} files")
        val violations = files.flatMap { violationsIn(it, SourceRoots.relativePath(it)) }
        assertEquals(
            emptyList<String>(),
            violations,
            "src/main/kotlin must not name a CLI backend, a per-CLI setting, backends.cli or the terminal " +
                "launcher (D-06, D-07). Move the code to src/full or go through an SPI.",
        )
    }

    @Test
    fun everyPatternFiresOnASyntheticLine() {
        val samples =
            mapOf(
                "cli backend id" to listOf(
                    "registerCard(\"codex-cli\", card)",
                    "\"gemini-cli\" -> 3.7",
                    "id == \"opencode-cli\"",
                    "// claude-cli keeps its ratio",
                    "backends.get(\"copilot-cli\")",
                ),
                "per-CLI setting" to listOf(
                    "val codexCmd: String",
                    "settings.geminiCmd",
                    "opencodeCmd = x",
                    "claudeCmd.text",
                    "copilotCmd",
                    "ollamaCliCmd.isBlank()",
                    "val cliTimeoutSeconds: Int = 120",
                    "cliTimeoutSeconds = settings.cliTimeoutSeconds",
                ),
                "backends.cli package" to listOf(
                    "import com.six2dez.burp.aiagent.backends.cli.CliBackend",
                    "package com.six2dez.burp.aiagent.backends.cli",
                ),
                "terminal launcher" to listOf(
                    "openExternalCli(backendId, command)",
                    "CliTerminalLauncher.openExternalCli(api, null, id, cmd)",
                ),
            )
        samples.forEach { (name, lines) ->
            lines.forEach { line ->
                val hits = violationsIn(fakeFile(line), "Synthetic.kt")
                assertEquals(1, hits.size, "$name must fire on `$line`, got $hits")
                assertTrue(hits.single().startsWith("Synthetic.kt:1 "), "the violation names file:line, got $hits")
            }
        }
    }

    @Test
    fun theGenericLaunchSpecMembersAreAllowed() {
        val allowed =
            mapOf(
                "com/six2dez/burp/aiagent/backends/BackendTypes.kt" to "    val cliTimeoutSeconds: Int? = null,",
                "com/six2dez/burp/aiagent/audit/PromptBundle.kt" to "    val cliTimeoutSeconds: Int?,",
            )
        allowed.forEach { (path, line) ->
            assertEquals(emptyList<String>(), violationsIn(fakeFile(line), path), "$path: `$line` is the generic launch-spec member")
        }
        assertEquals(
            emptyList<String>(),
            violationsIn(fakeFile("                cliTimeoutSeconds = config.cliTimeoutSeconds,"), "com/six2dez/burp/aiagent/audit/PromptBundle.kt"),
        )
        assertEquals(emptyList<String>(), violationsIn(fakeFile("    val cliSessionId: String? = null,"), "Any.kt"))
        assertEquals(1, violationsIn(fakeFile("    val cliTimeoutSeconds: Int? = null,"), "com/six2dez/burp/aiagent/config/AgentSettings.kt").size)
    }

    private fun violationsIn(
        file: File,
        displayPath: String,
    ): List<String> =
        file.readLines().mapIndexedNotNull { index, line ->
            val pattern = PATTERNS.entries.firstOrNull { (_, regex) -> regex.containsMatchIn(line) }?.key
            when {
                pattern == null -> null
                isAllowedLaunchSpecLine(displayPath, line) -> null
                else -> "$displayPath:${index + 1} [$pattern] ${line.trim()}"
            }
        }

    private fun isAllowedLaunchSpecLine(
        path: String,
        line: String,
    ): Boolean {
        val trimmed = line.trim()
        val allowedLines = ALLOWED_LAUNCH_SPEC_LINES[path] ?: return false
        return trimmed in allowedLines && PATTERNS.entries.count { (_, regex) -> regex.containsMatchIn(line) } == 1
    }

    private fun fakeFile(line: String): File =
        File.createTempFile("core-backend-names", ".kt").apply {
            deleteOnExit()
            writeText(line + "\n")
        }

    private companion object {
        const val MIN_EXPECTED_FILES = 100

        val PATTERNS =
            linkedMapOf(
                "cli backend id" to Regex("""\b(codex|gemini|opencode|claude|copilot)-cli\b"""),
                "per-CLI setting" to Regex("""\b(codexCmd|geminiCmd|opencodeCmd|claudeCmd|copilotCmd|ollamaCliCmd|cliTimeoutSeconds)\b"""),
                "backends.cli package" to Regex("""\bbackends\.cli\b"""),
                "terminal launcher" to Regex("""\b(openExternalCli|CliTerminalLauncher)\b"""),
            )

        // OQ5: BackendLaunchConfig.cliTimeoutSeconds, declared in BackendTypes.kt and copied into the
        // audit PromptBundle. Exact trimmed lines, so any other use in those files still fails.
        val ALLOWED_LAUNCH_SPEC_LINES =
            mapOf(
                "com/six2dez/burp/aiagent/backends/BackendTypes.kt" to setOf("val cliTimeoutSeconds: Int? = null,"),
                "com/six2dez/burp/aiagent/audit/PromptBundle.kt" to
                    setOf("val cliTimeoutSeconds: Int?,", "cliTimeoutSeconds = config.cliTimeoutSeconds,"),
            )
    }
}
