package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 33 / D-11, D-12, LIFE-03 — no production file outside the thread helper builds a thread, a pool,
 * a timer or a shared-dispatcher coroutine scope.
 *
 * Every extension thread must be daemon, named `burp-ai-agent-<subsystem>` and tracked for the unload
 * sweep, and `util/ExtensionThreads.kt` is the one place that guarantees all three. Coroutine work the
 * extension starts runs on the extension-owned dispatcher in `mcp/McpCoroutines.kt`, which unload closes;
 * kotlinx's shared `Dispatchers.IO` / `Dispatchers.Default` and `GlobalScope` keep unnamed workers alive
 * for 60 s after an unload. A bare construction anywhere else would reach a reviewer's thread dump as an
 * unnamed or surviving thread, so this guard fails on it instead.
 *
 * The walk covers both production roots through [SourceRoots.kotlinFiles] (which fails on a missing or
 * empty root) and reads comment-stripped code lines: a line whose first non-space characters open a line
 * comment, continue a KDoc or open a block comment is skipped, the rule SchedulerGuardCoverageTest
 * applies. The allowlist is compared by package-relative path, so a file that moves between
 * `src/main` and `src/full` keeps its entry.
 *
 * Calls that only READ or WAIT on a thread are not constructions and do not match: `Thread.currentThread()`,
 * `Thread.sleep(..)`, `isEventDispatchThread()`, `ThreadPoolExecutor.AbortPolicy()`, `Executors.callable(..)`.
 * `javax.swing.Timer` runs its action on the EDT and owns no thread of ours, so it is allowed.
 */
class ThreadCreationGuardTest {
    @Test
    fun noProductionFileOutsideTheHelperBuildsAThreadPoolTimerOrSharedCoroutineScope() {
        val files = SourceRoots.kotlinFiles()
        SourceRoots.PRODUCTION.forEach { name ->
            val root = SourceRoots.root(name).canonicalFile.toPath()
            assertTrue(
                files.any { it.canonicalFile.toPath().startsWith(root) },
                "the walk saw no Kotlin file under `$name`, so this guard would pass over it without reading it",
            )
        }

        val hits =
            files
                .filterNot { SourceRoots.packageRelativePath(it) in ALLOWLIST }
                .flatMap { file -> findForbidden(SourceRoots.relativePath(file), file.readLines()) }

        assertTrue(
            hits.isEmpty(),
            "A production file builds a thread, a pool, a timer or a shared coroutine scope outside the helper " +
                "(Phase 33 / D-11, D-12, LIFE-03). Build the thread through ExtensionThreads (named " +
                "burp-ai-agent-<subsystem>, daemon, tracked for the unload sweep), or run the coroutine on a " +
                "scope over McpCoroutines.dispatcher().\n" +
                hits.joinToString("\n") { "  ${it.location}: ${it.token} -> ${it.line.trim()}" },
        )
    }

    @Test
    fun theAllowlistNamesExactlyTheHelperAndTheMcpDispatcher() {
        assertEquals(setOf("util/ExtensionThreads.kt", "mcp/McpCoroutines.kt"), ALLOWLIST)
        // SourceRoots.packageFile fails when a file is in no root or in both, so a renamed helper
        // cannot leave a stale entry that exempts nothing.
        ALLOWLIST.forEach { path -> assertTrue(SourceRoots.packageFile(path).isFile, "allowlisted `$path` must exist") }
    }

    @Test
    fun theMatcherReportsEachForbiddenTokenOnASyntheticLine() {
        // Fail-first proof: if a matcher stopped matching, the whole-tree guard above would pass over a
        // tree that builds that kind of thread again.
        val cases =
            listOf(
                THREAD to """val t = Thread(r, "x")""",
                THREAD to "val t = Thread { work() }",
                THREAD to "private val worker = object : Thread() {",
                THREAD to "val t = java.lang.Thread(r)",
                EXECUTORS to "val pool = Executors.newSingleThreadExecutor()",
                EXECUTORS to "val pool = java.util.concurrent.Executors.newFixedThreadPool(2)",
                RAW_POOL to "val pool = ThreadPoolExecutor(1, 1, 0L, TimeUnit.SECONDS, queue)",
                RAW_POOL to "val pool = ScheduledThreadPoolExecutor(1)",
                THREAD_FACTORY to """val factory = ThreadFactory { r -> named(r, "x") }""",
                KOTLIN_THREAD to "thread(start = true) { work() }",
                KOTLIN_THREAD to "import kotlin.concurrent.thread",
                JAVA_TIMER to "val timer = java.util.Timer()",
                JAVA_TIMER to "val task = object : TimerTask() {",
                SHARED_COROUTINES to "val scope = CoroutineScope(Dispatchers.IO)",
                SHARED_COROUTINES to "withContext(Dispatchers.Default) { work() }",
                SHARED_COROUTINES to "GlobalScope.launch { work() }",
                SHARED_COROUTINES to """val context = newSingleThreadContext("x")""",
                SHARED_COROUTINES to "val context = newFixedThreadPoolContext(2, \"x\")",
                OTHER_POOLS to "ForkJoinPool.commonPool().execute(task)",
                OTHER_POOLS to "val worker = object : SwingWorker<Unit, Unit>() {",
                OTHER_POOLS to "CompletableFuture.supplyAsync { work() }",
                OTHER_POOLS to "CompletableFuture.runAsync(task)",
                OTHER_POOLS to "list.parallelStream().forEach { work(it) }",
            )
        cases.forEach { (token, line) ->
            val hits = findForbidden("synthetic/Fixture.kt", listOf("package x", line))
            assertEquals(
                listOf("synthetic/Fixture.kt:2 $token"),
                hits.map { "${it.location} ${it.token}" },
                "the matcher did not report `$token` (and only it) on: $line",
            )
        }
    }

    @Test
    fun theMatcherIgnoresReadsWaitsAllowedTimersAndCommentLines() {
        val lines =
            listOf(
                "val me = Thread.currentThread()",
                "Thread.sleep(100)",
                "val t = javax.swing.Timer(1000) { refresh() }",
                "val policy = ThreadPoolExecutor.AbortPolicy()",
                "val callable = Executors.callable(r)",
                "if (SwingUtilities.isEventDispatchThread()) return",
                "val x = 1 // runs on a daemon thread (Phase 23)",
                "val pool = ExtensionThreads.singleThread(\"health\")",
                "val worker = ExtensionThreads.newThread(\"service-x\") { pump() }",
                "// Thread(r, \"x\") used to be built here",
                " * Executors.newFixedThreadPool(2) is gone; see ExtensionThreads",
                "/* GlobalScope.launch { } */",
                "    // withContext(Dispatchers.IO) { }",
            )
        assertEquals(
            emptyList<String>(),
            findForbidden("synthetic/Fixture.kt", lines).map { "${it.location} ${it.token}" },
            "reads, waits, the Swing timer, helper calls and comment lines must not be reported",
        )
    }

    private data class Hit(
        val location: String,
        val token: String,
        val line: String,
    )

    /** Every forbidden token on a code line of [lines], reported as `path:line`; comment lines are skipped. */
    private fun findForbidden(
        relativePath: String,
        lines: List<String>,
    ): List<Hit> =
        lines.withIndex().filterNot { (_, line) -> line.isCommentLine() }.flatMap { (index, line) ->
            TOKENS
                .filter { (_, pattern) -> pattern.containsMatchIn(line) }
                .map { (token, _) -> Hit("$relativePath:${index + 1}", token, line) }
        }

    /** A line comment, a KDoc continuation or a block-comment opener (the three markers spelled out in the class KDoc). */
    private fun String.isCommentLine(): Boolean {
        val trimmed = trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private companion object {
        /** Package-relative paths of the only files allowed to build threads and dispatchers. */
        val ALLOWLIST = setOf("util/ExtensionThreads.kt", "mcp/McpCoroutines.kt")

        const val THREAD = "Thread construction"
        const val EXECUTORS = "Executors factory"
        const val RAW_POOL = "raw ThreadPoolExecutor"
        const val THREAD_FACTORY = "ThreadFactory literal"
        const val KOTLIN_THREAD = "kotlin thread()"
        const val JAVA_TIMER = "java.util.Timer"
        const val SHARED_COROUTINES = "shared coroutine dispatcher"
        const val OTHER_POOLS = "other thread pool"

        /**
         * RESEARCH "Source guard matcher (D-11)", with three additions measured against synthetic lines:
         * fully qualified `java.lang.Thread(` and `kotlin.concurrent.thread` (the leading `.` would
         * otherwise slip past the lookbehind), and a trailing lambda after `supplyAsync` / `runAsync`. The
         * kotlin `thread(` matcher allows no space before the parenthesis, so prose like "a daemon thread
         * (Phase 23)" in a trailing comment never matches.
         */
        // RED: no matcher yet.
        val TOKENS: List<Pair<String, Regex>> = emptyList()
    }
}
