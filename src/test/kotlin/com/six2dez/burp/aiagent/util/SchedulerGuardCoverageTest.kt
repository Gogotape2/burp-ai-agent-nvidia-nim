package com.six2dez.burp.aiagent.util

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * REL-06 / SC1 — the structural half of the scheduler guarantee.
 *
 * Phase 23 D-02 ratified the shape: the guarantee lives in two places at once. [GuardedSchedulingTest]
 * proves the mechanism works; this suite proves every recurring schedule in the codebase actually
 * uses it. A helper nobody is required to call is a helper the sixth call site will skip.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml:47` passes. `SchedulerGuardCoverageTest` is the
 * approved name precisely because the natural one — `SchedulerSupervisionTest` — ends in an excluded
 * suffix and would have made this guard silently stop running on the PR gate.
 *
 * **Comment stripping is load-bearing, not cosmetic.** The guarded files name the very tokens counted
 * here in their own KDoc and inline comments, so a reader that did not strip comments would count
 * documentation as a call site. It is also what makes it safe for `GuardedScheduling.kt` to explain
 * the failure mode in prose.
 *
 * **This suite reads source from disk**, from both production roots (`src/main/kotlin` and
 * `src/full/kotlin`, through [SourceRoots]). `build.gradle.kts` therefore declares both as
 * `inputs.dir` on the Test tasks, under the property names `mainSourceTreeStructuralInputs` and
 * `fullSourceTreeStructuralInputs`. Without them, adding an unguarded scheduler can produce a cache key
 * close enough that the test task is served from cache and this guard never runs — in exactly the
 * commit that breaks the invariant (the measured 22-09 defect).
 */
class SchedulerGuardCoverageTest {
    /**
     * REL-06-D — the allowlist. Every file under either production root (`src/main/kotlin`,
     * `src/full/kotlin`) that still calls a recurring schedule directly must be one of the three that
     * are allowed to.
     *
     * Compared as a **sorted set of file names**, never a list: a directory walk returns files in
     * filesystem order, which is not stable across platforms, and an order-sensitive assertion would
     * be flaky by construction (A-EDGE-3).
     */
    @Test
    fun everyRecurringScheduleUnderMainSourceIsOnTheGuardAllowlist() {
        val actual = filesWithRecurringSchedule().map { it.name }.toSortedSet()

        assertEquals(
            ALLOWLIST.toSortedSet(),
            actual,
            "REL-06 scheduler allowlist. Exactly three files under ${SourceRoots.PRODUCTION} may call " +
                "a recurring schedule directly:\n" +
                "  - GuardedScheduling.kt — the guard helper itself; the one place the JDK call is made.\n" +
                "  - AgentSupervisor.kt — the health monitor's pre-existing inline try/catch guard.\n" +
                "  - ActiveAiScanner.kt — the OAST poller's pre-existing inline try/catch guard.\n" +
                "Any OTHER file name in this set means a new recurring schedule was added that bypasses " +
                "`scheduleGuarded`, so a single throw in its body will silently cancel it for the rest " +
                "of the Burp session with nothing in the error log. Route it through " +
                "`ScheduledExecutorService.scheduleGuarded` in `util/GuardedScheduling.kt`. A MISSING " +
                "name means a guarded site was removed or renamed — update this allowlist deliberately, " +
                "never reflexively.\n" +
                "Actual: $actual",
        )
    }

    /**
     * The two grandfathered survivors really are guarded, rather than merely being on the list by
     * name. Without this, deleting `AgentSupervisor`'s inline `try` would leave assertion 1 green.
     */
    @Test
    fun everyAllowlistedRecurringScheduleOutsideTheHelperOpensATryImmediatelyBelowIt() {
        filesWithRecurringSchedule()
            .filterNot { it.name == GUARD_HELPER }
            .forEach { file ->
                val code = codeLinesOf(file)
                code.forEachIndexed { index, line ->
                    if (!line.isRecurringSchedule()) return@forEachIndexed
                    val lookahead = code.subList(index + 1, minOf(index + 1 + GUARD_LOOKAHEAD_LINES, code.size))
                    assertTrue(
                        lookahead.any { it.contains(TRY_OPENER) },
                        "${file.name} calls a recurring schedule at code line ${index + 1} " +
                            "(`${line.trim()}`) but opens no `$TRY_OPENER` within the next " +
                            "$GUARD_LOOKAHEAD_LINES code lines. This file is on the REL-06 allowlist ONLY " +
                            "because it carries an inline guard; without the guard it must be migrated to " +
                            "`scheduleGuarded` instead of staying on the list.",
                    )
                }
            }
    }

    /**
     * A-EDGE-1 (adjacency) positive control — `schedule(` is a prefix of both recurring tokens, and
     * the two one-shot call sites must NOT be swept into the allowlist by a sloppier match.
     */
    @Test
    fun oneShotScheduleCallSitesAreDeliberatelyOutOfRel06Scope() {
        val matched = filesWithRecurringSchedule().map { it.name }.toSortedSet()

        ONE_SHOT_SCHEDULERS.forEach { name ->
            assertTrue(
                name !in matched,
                "$name uses a one-shot `schedule(` and must stay OUT of the REL-06 allowlist. A " +
                    "one-shot task that throws fails only itself — it has no subsequent execution for " +
                    "the JDK to suppress — so it is deliberately out of scope. Its appearance here means " +
                    "the match widened from the two full recurring tokens to a bare `schedule(` prefix, " +
                    "which would make this guard fire on code it has no claim over. Matched: $matched",
            )
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /**
     * Every production `.kt` file with a recurring schedule. [SourceRoots.kotlinFiles] walks both
     * production roots and fails on a missing or empty root rather than returning an empty walk — an
     * empty result would make all three assertions vacuously green, which is the one failure mode a
     * structural guard must never have. File NAMES are what the allowlist compares, so a file that moves
     * between `src/main/kotlin` and `src/full/kotlin` keeps matching its entry.
     */
    private fun filesWithRecurringSchedule(): List<File> = SourceRoots.kotlinFiles().filter { file -> codeLinesOf(file).any { it.isRecurringSchedule() } }

    private fun String.isRecurringSchedule(): Boolean = contains(AT_FIXED_RATE) || contains(WITH_FIXED_DELAY)

    /**
     * The non-comment lines of [file], read from disk.
     *
     * A line counts as a comment when its first non-space characters are a line-comment marker, a
     * continuation asterisk, or a block-comment opener — the same rule
     * `SettingsPersistQueueTest.codeLinesOf` applies. (The three markers are written out longhand
     * rather than quoted, because Kotlin block comments nest: a literal opener inside this KDoc would
     * open a nested comment and swallow the rest of the file.)
     */
    private fun codeLinesOf(file: File): List<String> {
        assertTrue(
            file.isFile,
            "Expected `${file.path}` to be a readable file, resolved as `${file.absolutePath}`. If the " +
                "build layout changed, fix the path here and in the matching `tasks.test` input " +
                "declaration (`mainSourceTreeStructuralInputs` in build.gradle.kts).",
        )
        return file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }
    }

    private companion object {
        const val GUARD_HELPER = "GuardedScheduling.kt"
        const val TRY_OPENER = "try {"
        const val GUARD_LOOKAHEAD_LINES = 4

        /** The two FULL recurring tokens. Never a bare `schedule(` — see A-EDGE-1 above. */
        const val AT_FIXED_RATE = "scheduleAtFixedRate("
        const val WITH_FIXED_DELAY = "scheduleWithFixedDelay("

        val ALLOWLIST = listOf(GUARD_HELPER, "AgentSupervisor.kt", "ActiveAiScanner.kt")

        val ONE_SHOT_SCHEDULERS = listOf("ExternalMcpClientManager.kt", "McpSupervisor.kt")
    }
}
