package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Phase 29 (BUILD-01 adjacency edge, RESEARCH Pitfall 4): no package-relative Kotlin path may exist in
 * both production roots.
 *
 * Top-level functions in `mcp/tools/McpToolHelpers.kt` compile to `...mcp.tools.McpToolHelpersKt`. If
 * `src/full/kotlin` also held an `McpToolHelpers.kt` in the same package, the full JAR would carry two
 * `McpToolHelpersKt` classes; the shadow merge keeps one and the other side fails at runtime with
 * `NoSuchMethodError`. A same-named file in a DIFFERENT package is a different class and is fine, so the
 * check compares package-relative paths, never bare file names.
 *
 * Resource files under `META-INF/services` are out of scope on purpose: the full JAR merges them.
 *
 * This file also pins the [SourceRoots] contract the disk-walking guards depend on: both roots walked,
 * a missing or empty root fails, and a pinned path must sit in exactly one root.
 */
class SourceSetCollisionTest {
    @TempDir
    lateinit var temp: File

    // ── the collision guard ───────────────────────────────────────────────────────────────

    @Test
    fun theProductionRootsShareNoPackageRelativeKotlinPath() {
        val colliding = collidingPaths(SourceRoots.layout(), SourceRoots.MAIN, SourceRoots.FULL)

        assertTrue(
            colliding.isEmpty(),
            "These package-relative Kotlin paths exist in BOTH ${SourceRoots.MAIN} and " +
                "${SourceRoots.FULL}: $colliding. Each pair compiles to one facade class name, and the " +
                "full JAR keeps only one of the two (RESEARCH Pitfall 4). Give the src/full copy a " +
                "unique file name in the same package (for example GenericToolHelpers.kt).",
        )
    }

    @Test
    fun theTestRootsShareNoPackageRelativeKotlinPath() {
        // fullTest compiles against the test output, so a same-named test file in the same package would
        // shadow one class with the other on the fullTest classpath.
        val colliding = collidingPaths(SourceRoots.layout(), SourceRoots.TEST, SourceRoots.FULL_TEST)

        assertTrue(
            colliding.isEmpty(),
            "These package-relative Kotlin paths exist in BOTH ${SourceRoots.TEST} and " +
                "${SourceRoots.FULL_TEST}: $colliding. Rename the src/fullTest copy.",
        )
    }

    @Test
    fun theCollisionCheckFiresOnASyntheticCollision() {
        // Positive control: without it, a check that can never fire reads as a collision-free tree.
        kotlinFile(SourceRoots.MAIN, "com/example/tools/Helpers.kt")
        kotlinFile(SourceRoots.FULL, "com/example/tools/Helpers.kt")
        // Same file NAME in a different package: a different class, so NOT a collision.
        kotlinFile(SourceRoots.MAIN, "com/example/core/Models.kt")
        kotlinFile(SourceRoots.FULL, "com/example/generic/Models.kt")
        kotlinFile(SourceRoots.MAIN, "com/example/core/OnlyInMain.kt")

        val colliding = collidingPaths(SourceRoots.Layout(temp), SourceRoots.MAIN, SourceRoots.FULL)

        assertEquals(setOf("com/example/tools/Helpers.kt"), colliding)
    }

    // ── the SourceRoots contract ──────────────────────────────────────────────────────────

    @Test
    fun kotlinFilesWalksBothProductionRoots() {
        val paths = SourceRoots.kotlinFiles().map { SourceRoots.relativePath(it) }.toSet()

        assertTrue(
            APP_PATH in paths,
            "SourceRoots.kotlinFiles() did not reach $APP_PATH in ${SourceRoots.MAIN}.",
        )
        assertTrue(
            FULL_PROFILE_PATH in paths,
            "SourceRoots.kotlinFiles() did not reach $FULL_PROFILE_PATH in ${SourceRoots.FULL}. A walk " +
                "of one root is blind to every file the later plans move into the other.",
        )
    }

    @Test
    fun kotlinFilesFailsNamingAMissingRoot() {
        kotlinFile(SourceRoots.MAIN, "com/example/core/App.kt")

        val error = assertThrows(AssertionError::class.java) { SourceRoots.Layout(temp).kotlinFiles(SourceRoots.PRODUCTION) }

        assertTrue(
            error.message.orEmpty().contains(SourceRoots.FULL),
            "a missing ${SourceRoots.FULL} must fail naming that root. Message: ${error.message}",
        )
    }

    @Test
    fun kotlinFilesFailsNamingARootWithNoKotlinFile() {
        kotlinFile(SourceRoots.MAIN, "com/example/core/App.kt")
        File(temp, "${SourceRoots.FULL}/com/example/README.md").apply { parentFile.mkdirs() }.writeText("not kotlin")

        val error = assertThrows(AssertionError::class.java) { SourceRoots.Layout(temp).kotlinFiles(SourceRoots.PRODUCTION) }

        assertTrue(
            error.message.orEmpty().contains(SourceRoots.FULL) && error.message.orEmpty().contains("no Kotlin files"),
            "an empty ${SourceRoots.FULL} must fail naming that root. Message: ${error.message}",
        )
    }

    @Test
    fun fileResolvesARootRelativePathInTheRootThatHoldsIt() {
        assertEquals(
            File(SourceRoots.root(SourceRoots.MAIN), APP_PATH).canonicalFile,
            SourceRoots.file(APP_PATH).canonicalFile,
        )
        assertEquals(
            File(SourceRoots.root(SourceRoots.FULL), FULL_PROFILE_PATH).canonicalFile,
            SourceRoots.file(FULL_PROFILE_PATH).canonicalFile,
        )
        assertEquals("full/FullFlavorProfile.kt", SourceRoots.packageRelativePath(SourceRoots.file(FULL_PROFILE_PATH)))
        assertEquals("App.kt", SourceRoots.packageRelativePath(SourceRoots.packageFile("App.kt")))
    }

    @Test
    fun fileFailsNamingBothRootsWhenNoRootHoldsThePath() {
        val missing = "${SourceRoots.PACKAGE_DIR}/DoesNotExist.kt"

        val error = assertThrows(AssertionError::class.java) { SourceRoots.file(missing) }

        val message = error.message.orEmpty()
        assertTrue(
            message.contains(missing) && message.contains(SourceRoots.MAIN) && message.contains(SourceRoots.FULL),
            "a path in neither root must fail naming the path and both roots. Message: $message",
        )
    }

    @Test
    fun fileFailsNamingBothLocationsWhenBothRootsHoldThePath() {
        val main = kotlinFile(SourceRoots.MAIN, "com/example/tools/Helpers.kt")
        val full = kotlinFile(SourceRoots.FULL, "com/example/tools/Helpers.kt")

        val error =
            assertThrows(AssertionError::class.java) {
                SourceRoots.Layout(temp).exactlyOne(SourceRoots.PRODUCTION, "com/example/tools/Helpers.kt")
            }

        val message = error.message.orEmpty()
        assertTrue(
            message.contains(main.absolutePath) && message.contains(full.absolutePath),
            "a path in both roots must fail naming both locations. Message: $message",
        )
    }

    // ── fixture ───────────────────────────────────────────────────────────────────────────

    private fun kotlinFile(
        root: String,
        relativePath: String,
    ): File =
        File(temp, "$root/$relativePath").apply {
            parentFile.mkdirs()
            writeText("package ${relativePath.substringBeforeLast('/').replace('/', '.')}\n")
        }

    private companion object {
        const val APP_PATH = "${SourceRoots.PACKAGE_DIR}/App.kt"
        const val FULL_PROFILE_PATH = "${SourceRoots.PACKAGE_DIR}/full/FullFlavorProfile.kt"

        /** Package-relative Kotlin paths present under both roots of [layout]. */
        fun collidingPaths(
            layout: SourceRoots.Layout,
            first: String,
            second: String,
        ): Set<String> {
            fun pathsUnder(root: String): Set<String> {
                val dir = layout.root(root).canonicalFile
                return layout.kotlinFiles(listOf(root)).map { it.canonicalFile.relativeTo(dir).invariantSeparatorsPath }.toSet()
            }
            return pathsUnder(first).intersect(pathsUnder(second)).toSortedSet()
        }
    }
}
