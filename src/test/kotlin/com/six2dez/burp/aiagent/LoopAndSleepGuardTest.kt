package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 34 / D-05, LOOP-01 — no production file loops forever, sleeps a thread, parks a thread or polls a
 * child process.
 *
 * Round 4 of the BApp Store review cited `while (true)` + `Thread.sleep` loops. Phase 34 closed every site:
 * the string scans and the dialog re-prompt loop got explicit conditions, retry backoff moved to a
 * scheduled one-shot task, scanner pacing waits on the scanner's stop signal, the passive-scan session poll
 * was deleted, and every child-process wait got a deadline. This guard keeps them closed. Each token is
 * banned for one reason:
 *  - `while (true)` (also the `} while (true)` of a do-while): an unconditional loop hides its exit and is
 *    exactly the shape a reviewer greps for; spell the condition out instead.
 *  - `Thread.sleep(..)`, an import of `java.lang.Thread.sleep`, `TimeUnit.<UNIT>.sleep(..)`: a thread
 *    sleep holds a worker that stop and unload cannot release at once; wait on a signal or a scheduler.
 *  - `LockSupport.park*`: the same blocking wait one level lower.
 *  - `process.waitFor(<number>, ..)`: a fixed short timed wait is the polling idiom (the old 200 ms
 *    OpenCode poll); wait once on a deadline held in a named value instead.
 *  - `process.waitFor()`: a child-process wait with no deadline can hang forever (the old keytool wait).
 *
 * The walk covers both production roots through [SourceRoots.kotlinFiles] (which fails on a missing or
 * empty root). A line whose first non-space characters open a line comment, continue a KDoc or open a
 * block comment is skipped; a trailing comment after code is read like the code, so keep such prose out
 * of trailing comments. Recurring timers (scheduled executors, Swing timers) are not loops and are out of
 * scope; [ThreadCreationGuardTest] governs where their threads come from.
 */
class LoopAndSleepGuardTest {
    @Test
    fun noProductionFileLoopsForeverSleepsOrPolls() {
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
            "A production file loops forever, sleeps or parks a thread, or polls a child process " +
                "(Phase 34 / D-05, LOOP-01). Write the loop condition out, wait on a signal or a scheduled " +
                "task instead of sleeping, and wait on a child process once, with a deadline.\n" +
                hits.joinToString("\n") { "  ${it.location} ${it.token} -> ${it.line.trim()}" },
        )
    }

    @Test
    fun theAllowListIsEmpty() {
        // Every Phase 34 site was fixed rather than exempted; an entry here is a reviewed change to this test.
        assertEquals(emptyMap<String, String>(), ALLOWLIST)
    }

    @Test
    fun theMatcherReportsEachForbiddenTokenOnASyntheticLine() {
        // Fail-first proof: if a matcher stopped matching, the whole-tree guard above would pass over a
        // tree that sleeps or polls again.
        val cases =
            listOf(
                WHILE_TRUE to "while (true) {",
                WHILE_TRUE to "while(true){",
                WHILE_TRUE to "} while (true)",
                THREAD_SLEEP to "Thread.sleep(100)",
                THREAD_SLEEP to "java.lang.Thread.sleep(1)",
                THREAD_SLEEP to "import java.lang.Thread.sleep",
                TIMEUNIT_SLEEP to "TimeUnit.MILLISECONDS.sleep(5)",
                TIMEUNIT_SLEEP to "SECONDS.sleep(1)",
                PARK to "LockSupport.parkNanos(10)",
                SHORT_POLL to "process.waitFor(200, TimeUnit.MILLISECONDS)",
                UNBOUNDED_WAIT to "val code = process.waitFor()",
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
    fun theMatcherIgnoresConditionalLoopsDeadlineWaitsAndComments() {
        val lines =
            listOf(
                "while (idx >= 0) {",
                "while (asking) {",
                "latch.await(5, TimeUnit.SECONDS)",
                "process.waitFor(timeoutSeconds, TimeUnit.SECONDS)",
                "pacing.pause(requestDelayMs)",
                "// the old fixed sleep lived here: Thread.sleep(…)",
                " * while (true) is banned",
                "/* SECONDS.sleep(1) */",
            )
        assertEquals(
            emptyList<String>(),
            findForbidden("synthetic/Fixture.kt", lines).map { "${it.location} ${it.token}" },
            "conditional loops, deadline waits, signal waits and comment lines must not be reported",
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
        /** Package-relative path to the reason it may loop, sleep or poll. Empty since Phase 34. */
        val ALLOWLIST: Map<String, String> = emptyMap()

        const val WHILE_TRUE = "while (true)"
        const val THREAD_SLEEP = "Thread.sleep"
        const val TIMEUNIT_SLEEP = "TimeUnit sleep"
        const val PARK = "LockSupport.park"
        const val SHORT_POLL = "numeric-literal waitFor poll"
        const val UNBOUNDED_WAIT = "waitFor without deadline"

        /**
         * RESEARCH Pattern 5, plus the deadline-free `waitFor()` D-07 asks for. SHORT_POLL matches only a
         * numeric literal timeout, so a deadline held in a named value (`waitFor(timeoutSeconds, ..)`)
         * passes; the TimeUnit form matches with or without the `TimeUnit.` qualifier.
         */
        val TOKENS: List<Pair<String, Regex>> =
            listOf(
                WHILE_TRUE to Regex("""\bwhile\s*\(\s*true\s*\)"""),
                THREAD_SLEEP to Regex("""\bThread\s*\.\s*sleep\s*\(|^\s*import\s+java\.lang\.Thread\.sleep\b"""),
                TIMEUNIT_SLEEP to
                    Regex("""\b(?:NANOSECONDS|MICROSECONDS|MILLISECONDS|SECONDS|MINUTES|HOURS|DAYS)\s*\.\s*sleep\s*\("""),
                PARK to Regex("""\bLockSupport\s*\.\s*park"""),
                SHORT_POLL to Regex("""\.waitFor\s*\(\s*\d+\s*,"""),
                UNBOUNDED_WAIT to Regex("""\.waitFor\s*\(\s*\)"""),
            )
    }
}
