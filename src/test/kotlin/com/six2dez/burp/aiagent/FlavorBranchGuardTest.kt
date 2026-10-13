package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 29 (BUILD-04, ROADMAP SC4, D-16): no build-flavor branch, anywhere a reviewer or the build reads.
 *
 * The two flavors differ ONLY in which providers are packaged: the BApp Store JAR is `src/main`, the
 * GitHub JAR is `src/main` + `src/full`. Plan 29-08 retired the compile-time flavor constant, the Gradle
 * property that set it, the test system property that echoed it and the descriptor flag the tools tab
 * keyed on. A flavor switch that comes back — under its old name or as an `isBapp()` probe — would put
 * the store reviewer back in the position of reasoning about a branch instead of reading a JAR.
 *
 * This guard walks every production root ([SourceRoots.kotlinFiles]), `build.gradle.kts` and every file
 * under `.github/workflows`, and fails naming `file:line` when a forbidden token appears, comments
 * included: a comment that names the retired switch is a pointer to a mechanism that no longer exists.
 *
 * BOUND: it recognises the four NAMED tokens below and nothing else. A flavor switch spelled differently
 * (a new property name, a class-name probe through reflection) is invisible to it; review owns that.
 * The tokens are matched as substrings, case-sensitively, because the retired property also appeared
 * as a prefix (`-P...`) and a suffix (`....expected`), and an identifier-boundary match would miss both.
 */
class FlavorBranchGuardTest {
    @Test
    fun noFlavorBranchTokenAppearsInSourceBuildScriptOrWorkflows() {
        val hits = scannedFiles().flatMap { (path, file) -> findForbidden(path, file.readLines()) }
        assertTrue(
            hits.isEmpty(),
            "A build-flavor switch is back. Flavor differences come only from which providers are " +
                "packaged (BUILD-04): delete the branch rather than renaming it.\n" +
                hits.joinToString("\n") { "  ${it.location}: `${it.token.text}` (${it.token.reason}) -> ${it.line.trim()}" },
        )
    }

    @Test
    fun theScanReachesTheSourceTheBuildScriptAndEveryWorkflow() {
        // A guard that walks nothing passes vacuously; resolving the roots throws when one is missing.
        val scanned = scannedFiles().map { it.first }
        assertTrue(BUILD_SCRIPT in scanned, "the scan does not read $BUILD_SCRIPT")
        val workflows = scanned.filter { it.startsWith("$WORKFLOWS_DIR/") }
        assertTrue(
            workflows.size >= MIN_WORKFLOW_FILES,
            "the scan read only $workflows under $WORKFLOWS_DIR; expected at least $MIN_WORKFLOW_FILES files",
        )
        assertTrue(
            scanned.size - workflows.size - 1 >= MIN_PRODUCTION_FILES,
            "the scan read too few production Kotlin files to be guarding the tree",
        )
        // The one generated constant that legitimately stays is still produced by the script, so the
        // script read here is the real one rather than an empty stand-in.
        assertTrue(
            projectFile(BUILD_SCRIPT).readText().contains("const val VERSION"),
            "$BUILD_SCRIPT no longer generates BuildFlags.VERSION; the scan may be reading the wrong file",
        )
    }

    @Test
    fun eachForbiddenTokenIsReportedOnASyntheticLine() {
        // Fail-first proof: if a pattern stopped matching, the whole-tree guard above would pass over a
        // tree that still held the switch.
        FORBIDDEN_TOKENS.forEach { token ->
            val line = "    val x = ${token.sample} // synthetic"
            val hits = findForbidden("synthetic/Fixture.kt", listOf("package x", line))
            assertEquals(
                listOf("synthetic/Fixture.kt:2"),
                hits.filter { it.token == token }.map { it.location },
                "the matcher did not report `${token.text}` on a synthetic line that contains it",
            )
        }
        assertEquals(
            emptyList<String>(),
            findForbidden("synthetic/Fixture.kt", listOf("const val VERSION = \"1.0.1\"", "val isBappable = 1", "val NativeTools = 2"))
                .map { "${it.location} ${it.token.text}" },
            "lines that hold none of the tokens must not be reported (case-sensitive, `isBapp(` needs its paren)",
        )
    }

    private data class ForbiddenToken(
        val text: String,
        val sample: String,
        val reason: String,
    )

    private data class Hit(
        val location: String,
        val token: ForbiddenToken,
        val line: String,
    )

    private fun findForbidden(
        path: String,
        lines: List<String>,
    ): List<Hit> =
        lines.withIndex().flatMap { (index, line) ->
            FORBIDDEN_TOKENS.filter { line.contains(it.text) }.map { Hit("$path:${index + 1}", it, line) }
        }

    private fun projectFile(relative: String): File = File(SourceRoots.layout().projectDir, relative)

    /** Every scanned file as (display path, file): both production roots, the build script, every workflow. */
    private fun scannedFiles(): List<Pair<String, File>> {
        val kotlin = SourceRoots.kotlinFiles().map { SourceRoots.relativePath(it) to it }
        val script = projectFile(BUILD_SCRIPT)
        assertTrue(script.isFile, "expected $BUILD_SCRIPT at ${script.absolutePath}")
        val workflowsDir = projectFile(WORKFLOWS_DIR)
        assertTrue(workflowsDir.isDirectory, "expected $WORKFLOWS_DIR at ${workflowsDir.absolutePath}")
        val workflows =
            workflowsDir
                .walkTopDown()
                .filter { it.isFile }
                .map { "$WORKFLOWS_DIR/${it.relativeTo(workflowsDir).invariantSeparatorsPath}" to it }
                .toList()
        return kotlin + (BUILD_SCRIPT to script) + workflows
    }

    private companion object {
        const val BUILD_SCRIPT = "build.gradle.kts"
        const val WORKFLOWS_DIR = ".github/workflows"

        /** build.yml, nightly-regression.yml and release.yml at plan 29-08. A floor, not a count. */
        const val MIN_WORKFLOW_FILES = 3

        /** Floor for the production walk (180+ files at plan 29-08); catches a walk that reaches nothing. */
        const val MIN_PRODUCTION_FILES = 150

        val FORBIDDEN_TOKENS =
            listOf(
                ForbiddenToken(
                    "STORE_BUILD",
                    "BuildFlags.STORE_BUILD",
                    "BUILD-04: the compile-time flavor constant, retired by plan 29-08",
                ),
                ForbiddenToken(
                    "storeBuild",
                    "providers.gradleProperty(\"storeBuild\")",
                    "BUILD-04: the Gradle flavor property and its test system property, retired by plan 29-08",
                ),
                ForbiddenToken(
                    "isBapp(",
                    "if (isBapp()) 1 else 2",
                    "BUILD-04: a runtime flavor probe; the flavor is decided by packaging",
                ),
                ForbiddenToken(
                    "nativeTool",
                    "tool.nativeTool",
                    "BUILD-04: the descriptor flag the tools tab keyed on, retired by plan 29-08 for registry provenance",
                ),
            )
    }
}
