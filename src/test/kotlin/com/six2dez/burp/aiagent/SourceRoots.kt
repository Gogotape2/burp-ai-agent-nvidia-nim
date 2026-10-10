package com.six2dez.burp.aiagent

import java.io.File

/**
 * Phase 29 (BUILD-01, RESEARCH Pitfall 1): the production source roots that disk-reading guards walk.
 *
 * The build has two production source sets. `src/main/kotlin` is compiled into both JARs and
 * `src/full/kotlin` only into the full JAR. Later plans move whole files from one root to the other, so a
 * structural guard that walks a single root keeps passing while the code it guards has moved out from
 * under it. A pass that measures nothing is the one result a structural guard must never produce.
 *
 * Rules every caller relies on:
 *  - [kotlinFiles] walks EVERY production root and fails, naming the root, when a root is missing or
 *    yields no Kotlin file. It never returns an empty or partial walk.
 *  - [file] resolves a root-relative path ("com/six2dez/burp/aiagent/App.kt") in whichever root holds it.
 *    Exactly one root must hold it: a path in neither root and a path in both roots both fail.
 *  - [relativePath] and [packageRelativePath] turn a walked file back into a path that does not say which
 *    root it came from, so inventories keyed by path keep their keys when a file moves roots.
 *
 * The test roots ([TEST], [FULL_TEST]) exist for the one guard that sweeps test source rather than
 * production source (`RedactingPolicySurvivalSweepTest`); later plans move tests into `src/fullTest`.
 *
 * Every root is resolved from the project directory, found by walking up from `user.dir` to the first
 * directory that holds [MAIN]. Each root read here must also be declared as an `inputs.dir` of the Test
 * tasks in `build.gradle.kts` (`declareStructuralInputs`): Gradle cannot infer a file a test opens by
 * path, and an undeclared root lets a text-only edit be served from the build cache.
 */
internal object SourceRoots {
    const val MAIN = "src/main/kotlin"
    const val FULL = "src/full/kotlin"
    val PRODUCTION: List<String> = listOf(MAIN, FULL)
    const val PACKAGE_DIR = "com/six2dez/burp/aiagent"

    const val TEST = "src/test/kotlin"
    const val FULL_TEST = "src/fullTest/kotlin"
    val TESTS: List<String> = listOf(TEST, FULL_TEST)

    /** Every .kt file under every PRODUCTION root; asserts each root is a directory and yields >= 1 file. */
    fun kotlinFiles(): List<File> = layout().kotlinFiles(PRODUCTION)

    /** Every .kt file under every TESTS root, with the same non-vacuity rule as [kotlinFiles]. */
    fun testKotlinFiles(): List<File> = layout().kotlinFiles(TESTS)

    /** relativePath is under the root (e.g. "com/six2dez/burp/aiagent/App.kt"); exactly one root must hold it. */
    fun file(relativePath: String): File = layout().exactlyOne(PRODUCTION, relativePath)

    /** [file] for a path under [PACKAGE_DIR], e.g. "mcp/tools/McpToolHelpers.kt". */
    fun packageFile(packageRelativePath: String): File = file("$PACKAGE_DIR/$packageRelativePath")

    /** [file] over the TESTS roots. */
    fun testFile(relativePath: String): File = layout().exactlyOne(TESTS, relativePath)

    /**
     * Every PRODUCTION root's copy of [relativePath] that exists on disk: empty when no root holds it,
     * two entries when both do. For guards that count presence instead of failing on the first miss.
     */
    fun locate(relativePath: String): List<File> = layout().locate(PRODUCTION, relativePath)

    /** Path after "<root>/", e.g. "com/six2dez/burp/aiagent/App.kt", for a file under any production or test root. */
    fun relativePath(file: File): String = layout().relativePath(PRODUCTION + TESTS, file)

    /** Path after "<root>/com/six2dez/burp/aiagent/", e.g. "mcp/tools/McpToolHelpers.kt". */
    fun packageRelativePath(file: File): String {
        val relative = relativePath(file)
        val prefix = "$PACKAGE_DIR/"
        if (!relative.startsWith(prefix)) {
            throw AssertionError(
                "`$relative` is not under `$PACKAGE_DIR`, so it has no package-relative path. Every " +
                    "production file is expected to live in the extension's package tree.",
            )
        }
        return relative.removePrefix(prefix)
    }

    /** The resolved directory of one root ([MAIN], [FULL], [TEST] or [FULL_TEST]); fails if it is not a directory. */
    fun root(name: String): File = layout().root(name)

    /**
     * The roots of one project directory. [SourceRoots] uses the real project; tests build one over a
     * temporary directory to prove each failure fires.
     */
    class Layout(
        val projectDir: File,
    ) {
        fun root(name: String): File {
            val dir = File(projectDir, name)
            if (!dir.isDirectory) {
                throw AssertionError(
                    "Expected the source root `$name` at `${dir.absolutePath}` (project " +
                        "`${projectDir.path}`, user.dir `${System.getProperty("user.dir")}`). A guard " +
                        "that walks a missing root passes vacuously, so this fails instead. If the build " +
                        "layout changed, change SourceRoots and the matching declaration in " +
                        "build.gradle.kts (${inputProperty(name)}) together.",
                )
            }
            return dir
        }

        fun kotlinFiles(roots: List<String>): List<File> =
            roots.take(1).flatMap { name ->
                val dir = root(name)
                val files = dir.walkTopDown().filter { it.isFile && it.extension == KOTLIN_EXTENSION }.toList()
                if (files.isEmpty()) {
                    throw AssertionError(
                        "The walk of `$name` (`${dir.absolutePath}`) found no Kotlin files. Every " +
                            "assertion built on this walk would pass vacuously, so this is a failure " +
                            "rather than an empty result. If the root is meant to be empty, remove it from " +
                            "SourceRoots and from build.gradle.kts (${inputProperty(name)}) together.",
                    )
                }
                files
            }

        fun locate(
            roots: List<String>,
            relativePath: String,
        ): List<File> = roots.map { File(root(it), relativePath) }.filter { it.isFile }

        fun exactlyOne(
            roots: List<String>,
            relativePath: String,
        ): File {
            val present = locate(roots, relativePath)
            if (present.isNotEmpty()) return present.first()
            val message =
                if (present.isEmpty()) {
                    "`$relativePath` exists in none of the source roots $roots. Looked at: " +
                        "${roots.map { File(root(it), relativePath).absolutePath }}. If the file was " +
                        "renamed, update the pin; if it only moved roots it would have been found."
                } else {
                    "`$relativePath` exists in more than one source root: " +
                        "${present.map { it.absolutePath }}. Two same-named Kotlin files in one package " +
                        "compile to one facade class and the JAR keeps only one of them (RESEARCH " +
                        "Pitfall 4). Rename one of them."
                }
            throw AssertionError(message)
        }

        fun relativePath(
            roots: List<String>,
            file: File,
        ): String {
            val canonical = file.canonicalFile
            val holder =
                roots
                    .map { File(projectDir, it).canonicalFile }
                    .firstOrNull { canonical.toPath().startsWith(it.toPath()) }
                    ?: throw AssertionError(
                        "`${file.path}` (resolved as `${canonical.path}`) is under none of the source " +
                            "roots $roots of project `${projectDir.path}`. A guard asked for the relative " +
                            "path of a file it did not get from SourceRoots.",
                    )
            return canonical.relativeTo(holder).invariantSeparatorsPath
        }
    }

    private const val KOTLIN_EXTENSION = "kt"

    /** The `inputs.dir` declaration in build.gradle.kts that makes each root an input of the Test tasks. */
    private fun inputProperty(name: String): String =
        when (name) {
            MAIN -> "mainSourceTreeStructuralInputs"
            FULL -> "fullSourceTreeStructuralInputs"
            FULL_TEST -> "fullTestSourceTreeStructuralInputs"
            else -> "declareStructuralInputs"
        }

    /** The [Layout] of the real project directory: the first directory at or above `user.dir` that holds [MAIN]. */
    fun layout(): Layout {
        var candidate: File? = File(System.getProperty("user.dir")).absoluteFile
        while (candidate != null) {
            if (File(candidate, MAIN).isDirectory) return Layout(candidate)
            candidate = candidate.parentFile
        }
        throw AssertionError(
            "Could not find a project directory holding `$MAIN` at or above user.dir " +
                "`${System.getProperty("user.dir")}`. A repository-state test that goes green when it " +
                "cannot find the repository is worse than the grep it replaced, so this fails instead.",
        )
    }
}
