package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 31 / NET-01 (ROADMAP SC3): OkHttp is a test-only dependency, so no production source names it.
 *
 * Every provider request goes through `MontoyaHttpTransport`, so Burp's upstream proxy, its TLS settings
 * and the Use AI gate apply to it. A second HTTP client in production code would be a path around all
 * three, and PortSwigger's reviewer reads `src/full` as well as `src/main`. This guard walks every
 * production root through [SourceRoots.kotlinFiles] and fails, naming `file:line`, when a line names the
 * OkHttp package (`okhttp3`) or the Okio package (`okio.`). Comments and KDoc count too: a comment that
 * names OkHttp's package points at a client the build no longer has.
 *
 * The second test reads `build.gradle.kts` and asserts every `com.squareup.okhttp3` dependency is on
 * `testImplementation`, which the full test source set inherits. The JAR-level proof is
 * `StoreJarContentTest` (store JAR and full JAR).
 */
class NoOkHttpInProductionGuardTest {
    @Test
    fun noProductionSourceNamesOkHttpOrOkio() {
        val hits =
            SourceRoots.kotlinFiles().flatMap { file ->
                findOkHttpTokens(SourceRoots.relativePath(file), file.readLines())
            }
        assertTrue(
            hits.isEmpty(),
            "A production source names OkHttp or Okio. Provider traffic goes only through " +
                "MontoyaHttpTransport (Phase 31 / NET-01); OkHttp is a test-only dependency.\n" +
                hits.joinToString("\n") { "  ${it.location}: `${it.token}` -> ${it.line.trim()}" },
        )
    }

    @Test
    fun theMatcherReportsEachTokenOnASyntheticLine() {
        // Fail-first proof: if the matcher stopped matching, the whole-tree guard above would pass over a
        // tree that still imports OkHttp.
        listOf(
            "okhttp3" to "import okhttp3.OkHttpClient",
            "okio." to "import okio.Buffer",
        ).forEach { (token, line) ->
            val hits = findOkHttpTokens("synthetic/Fixture.kt", listOf("package x", line))
            assertEquals(
                listOf("synthetic/Fixture.kt:2 $token"),
                hits.map { "${it.location} ${it.token}" },
                "the matcher did not report `$token` on a synthetic import line",
            )
        }
        val commentHits = findOkHttpTokens("synthetic/Fixture.kt", listOf(" * the old okhttp3 client lived here"))
        assertEquals(1, commentHits.size, "a token in a KDoc line must be reported too")
    }

    @Test
    fun theMatcherIgnoresLinesWithoutEitherToken() {
        val lines =
            listOf(
                "val okHttpless = 1",
                "// MontoyaHttpTransport replaced the OkHttp client",
                "val bokio = 2",
                "import io.ktor.network.sockets.Socket",
            )
        assertEquals(
            emptyList<String>(),
            findOkHttpTokens("synthetic/Fixture.kt", lines).map { it.location },
            "lines that name neither the okhttp3 package nor the okio package must not be reported",
        )
    }

    @Test
    fun everyOkHttpDependencyIsTestImplementationOnly() {
        val buildScript = File(SourceRoots.layout().projectDir, BUILD_SCRIPT)
        assertTrue(buildScript.isFile, "Expected `$BUILD_SCRIPT` at `${buildScript.absolutePath}`")
        val lines = buildScript.readLines()
        val okHttpLines = lines.withIndex().filter { (_, line) -> line.contains(OKHTTP_GROUP) }
        assertTrue(
            okHttpLines.isNotEmpty(),
            "`$BUILD_SCRIPT` names no `$OKHTTP_GROUP` dependency. The MCP server tests need OkHttp as a " +
                "client, so a check over zero lines would pass vacuously.",
        )
        val misplaced = okHttpLines.filterNot { (_, line) -> line.trimStart().startsWith("testImplementation(") }
        assertTrue(
            misplaced.isEmpty(),
            "Every `$OKHTTP_GROUP` line in `$BUILD_SCRIPT` must start with `testImplementation(` " +
                "(Phase 31 / NET-01: OkHttp must not reach either runtime classpath):\n" +
                misplaced.joinToString("\n") { (index, line) -> "  $BUILD_SCRIPT:${index + 1}: ${line.trim()}" },
        )
    }

    private data class Hit(
        val location: String,
        val token: String,
        val line: String,
    )

    private fun findOkHttpTokens(
        relativePath: String,
        lines: List<String>,
    ): List<Hit> =
        lines.withIndex().flatMap { (index, line) ->
            TOKENS
                .filter { (_, pattern) -> pattern.containsMatchIn(line) }
                .map { (token, _) -> Hit("$relativePath:${index + 1}", token, line) }
        }

    private companion object {
        const val BUILD_SCRIPT = "build.gradle.kts"
        const val OKHTTP_GROUP = "com.squareup.okhttp3"

        /** Package tokens, matched where an identifier cannot continue to the left. */
        val TOKENS: List<Pair<String, Regex>> =
            listOf(
                "okhttp3" to Regex("""(?<![A-Za-z0-9_])okhttp3(?![A-Za-z0-9_])"""),
                "okio." to Regex("""(?<![A-Za-z0-9_])okio\."""),
            )
    }
}
