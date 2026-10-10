package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

private const val BASELINE_FILE = "detekt-baseline.xml"

/**
 * The `<ID>` count of the baseline. Phase 26 plan 07 sealed it at 1040 (trimmed from 1096 with a
 * removals-only diff); phase 29 plan 04 lowered it to 1032 in the commit that deleted the legacy MCP
 * registrar and its eight entries, then to 1031 in the commit that deleted Alerting and its one.
 *
 * This is a CEILING, not a target. ADR-17 clause 1 says the baseline may lose entries and may never
 * gain them, so the only edit this constant is ever allowed to receive is a DOWNWARD one, made in the
 * same commit as the removals that earned it. Raising it to make a build green converts a finding
 * somebody would otherwise have had to answer into a finding nobody will ever see again — which is
 * precisely the inversion ADR-17 clause 1 exists to forbid.
 */
private const val MAX_BASELINE_ENTRIES = 1031

/**
 * QUAL-07 / SC3 gate on ADR-17 clause 1 — "`detekt-baseline.xml` shrinks and is never appended to".
 *
 * **Why this exists.** ADR-17 states the shrink-only rule in prose and [DecisionsAdrTest] asserts that
 * the ADR still names the file, but neither one can observe the file's actual size. The one command
 * that could — `git diff -U0 <ref>..HEAD -- detekt-baseline.xml | grep -c '^+.*<ID>'` — lived inside a
 * plan document and ran once. A contributor who hits a new detekt finding and baselines it away
 * therefore breaks a written rule that nothing in `./gradlew check` is watching. This test is that
 * watcher.
 *
 * **What it can do.** It counts `<ID>` entries on disk and fails when the count exceeds the sealed
 * ceiling. That catches the whole failure mode the rule is about: appending an entry rather than
 * fixing the finding.
 *
 * **What it cannot do.** It cannot tell a removal-plus-addition pair that leaves the count level from
 * an honest no-op, and it cannot judge whether a removal was backed by a real source fix or by a stale
 * entry. Direction over a range of commits stays a `git diff` question; the count is what a build can
 * hold. The two are complementary, and neither substitutes for the other.
 *
 * **Cache note.** `build.gradle.kts` declares `detekt-baseline.xml` as an input of `tasks.test`. Without
 * that declaration a commit touching only the baseline produces byte-identical compiled output, the
 * test task is served from the build cache, and this guard reports green in exactly the commit that
 * breaks it. Do not remove the declaration.
 */
class DetektBaselineBoundTest {
    @Test
    fun theDetektBaselineNeverGrowsBeyondItsSealedEntryCount() {
        val baseline = File(BASELINE_FILE)
        assertTrue(
            baseline.isFile,
            "Expected to find `$BASELINE_FILE` relative to the test working directory " +
                "`${System.getProperty("user.dir")}`, resolved as `${baseline.absolutePath}`. " +
                "If the build layout changed, fix the path here rather than deleting this test — " +
                "it is the only automated check that ADR-17 clause 1 is honoured.",
        )

        val entries = Regex("<ID>").findAll(baseline.readText()).count()

        assertTrue(
            entries <= MAX_BASELINE_ENTRIES,
            "`$BASELINE_FILE` now holds $entries `<ID>` entries, above the sealed ceiling of " +
                "$MAX_BASELINE_ENTRIES. ADR-17 clause 1: the detekt baseline shrinks and is never " +
                "appended to — a finding introduced by new work is FIXED IN SOURCE, not baselined. " +
                "Fix the finding, or suppress it inline, narrowly scoped and with its reason stated. " +
                "Do NOT raise MAX_BASELINE_ENTRIES: it may only ever be lowered, in the same commit " +
                "as the removals that earned the lower number.",
        )
    }

    @Test
    fun theSealedCeilingStillMatchesADocumentedShrinkRatherThanADriftedNumber() {
        val entries = Regex("<ID>").findAll(File(BASELINE_FILE).readText()).count()

        assertTrue(
            entries in 1..MAX_BASELINE_ENTRIES,
            "`$BASELINE_FILE` holds $entries `<ID>` entries. An empty or unreadable baseline is not a " +
                "shrink — it is a lost file, and it would make the ceiling assertion above pass " +
                "vacuously.",
        )
    }
}
