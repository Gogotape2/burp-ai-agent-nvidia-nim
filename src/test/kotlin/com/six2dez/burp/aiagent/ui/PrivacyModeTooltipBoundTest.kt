package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

// The three clauses this file pins. Asserted as SUBSTRINGS, never as a whole tooltip: a full-string
// assertion would turn every future copy edit into a test failure and would end up maintained by
// pasting rather than by thinking. That is the same discipline PrivacyNoticeCompositionTest applies
// to the privacy notice, and it is stated here rather than cross-referenced so a reader meeting this
// file first does not "tighten" it into an equality check.
private const val PURPOSE_CLAUSE = "Controls how traffic is redacted before sending to a model"

/**
 * The forward-only claim, AT ITS TRUE SCOPE.
 *
 * NARROWED 2026-08-28 (phase 28 UAT test 2, closing `28-REVIEW-3.md` WR-05). This was previously the
 * blanket sentence `Applies from now on, not retroactively`, which is FALSE for the dominant path —
 * `McpToolContext.redactIfNeeded` re-redacts every MCP tool result under the CURRENT mode, so for
 * ordinary captured traffic a switch to STRICT *is* retroactive. Scanner findings are the only
 * genuinely forward-only case, so the pin moves onto the half-sentence that says so with its scope
 * attached. The claim is still pinned; it is no longer pinned in a form the product contradicts.
 *
 * WHY THE SUBJECT IS PART OF THE NEEDLE. The first draft of this pin was the bare predicate
 * `keep the values they were built with`, which does not carry its own subject — so
 * `Recorded findings and captured requests keep the values they were built with` would have
 * satisfied every test in this file while reintroducing the exact over-broad claim the narrowing
 * removed. The negative pin below catches only the LITERAL retired sentence, not a reworded one.
 * Including `Scanner findings already recorded` makes the SCOPE part of what is pinned, which is
 * the thing that actually matters here. Found by the round-4 verifier reviewing this file's own
 * change; the earlier form was not a regression (the pin it replaced mandated the false sentence)
 * but it was a tripwire that did not reach as far as its test name implied.
 */
private const val FORWARD_ONLY_CLAUSE = "Scanner findings already recorded keep the values they were built with"

/**
 * The blanket form this copy used to carry, kept ONLY so a test can assert its absence.
 *
 * Retired 2026-08-28. Named here rather than inlined so the negative pin below reads as a
 * deliberate retirement with a reason, not as an arbitrary string the next reader might delete.
 */
private const val RETIRED_BLANKET_CLAUSE = "Applies from now on, not retroactively"
private const val RECORDED_FINDINGS_CLAUSE = "re-scanning does not rewrite them"

/**
 * (PRIV-05) Phase 28 plan 28-07 — the WRITE-TIME/READ-TIME BOUND, pinned where an operator meets it.
 *
 * WHAT THIS FILE IS FOR. `D-28-09` accepted, as a named residual, that both cookie controls decide
 * ONCE at issue construction and bake the result into the immutable `AuditIssue.detail()` string, so
 * a finding built while `privacyMode` was `OFF` still emits the raw cookie value on a later STRICT
 * read, and `AiScanCheck.consolidateIssues`'s `KEEP_EXISTING` means a re-scan does not repair it.
 * `D-28-10` made that acceptance CONDITIONAL on the bound being NAMED — including at the one surface
 * where an operator states an intent about redaction. [PRIVACY_MODE_TOOLTIP] is that surface, and
 * this file is what stops the naming from being a one-round gesture the next copy edit removes.
 *
 * WHY THE CONSTANT EXISTS AT ALL. The tooltip was previously an inline literal inside
 * `SettingsPanel.initUiWiring()`, an extension function needing a live `SettingsPanel`, so it was
 * unreachable from a unit test. Extracting it to an `internal` top-level constant is what makes the
 * string the panel shows and the string this file asserts THE SAME OBJECT rather than two copies
 * that can drift apart. The source-scan test below is what keeps them from drifting back.
 *
 * WHAT THIS FILE DOES NOT PROVE. It does not prove an operator READ the tooltip, and it does not
 * prove the bound is fixed — the bound is a residual, not a closed defect. It proves only that the
 * copy naming it is present, is reachable from the single assignment site, and is ADDED to the
 * purpose sentence rather than substituted for it.
 */
class PrivacyModeTooltipBoundTest {
    /** The forward-only clause — half one of `D-28-10`'s operator-facing condition. */
    @Test
    fun theTooltipNamesScannerFindingsAsForwardOnly() {
        assertTrue(
            PRIVACY_MODE_TOOLTIP.contains(FORWARD_ONLY_CLAUSE),
            "PRIVACY_MODE_TOOLTIP must contain the forward-only clause '$FORWARD_ONLY_CLAUSE'. " +
                "Without it an operator switching to STRICT reads the selector as repairing " +
                "already-recorded findings, which is the false belief D-28-10 made the acceptance " +
                "of D-28-09's residual conditional on preventing. Tooltip was: $PRIVACY_MODE_TOOLTIP",
        )
    }

    /**
     * THE FORWARD-ONLY CLAIM IS NOT MADE BLANKET.
     *
     * The assertion above would be satisfied by a tooltip that ALSO carried an unscoped
     * `Applies from now on, not retroactively` — which is what shipped between plan 28-07 and this
     * UAT, and which is false for the dominant path: `McpToolContext.redactIfNeeded` applies
     * `Redaction.apply` under the CURRENT mode to every MCP tool result, so switching to STRICT re-
     * redacts ordinary captured traffic. This test is what stops the blanket form coming back as a
     * well-meaning copy edit. It is a NEGATIVE pin, and it is deliberate: erring pessimistic is
     * still erring, in the one place an operator is least able to check.
     */
    @Test
    fun theTooltipDoesNotMakeAnUnscopedForwardOnlyClaim() {
        assertFalse(
            PRIVACY_MODE_TOOLTIP.contains(RETIRED_BLANKET_CLAUSE),
            "PRIVACY_MODE_TOOLTIP must NOT contain the unscoped clause '$RETIRED_BLANKET_CLAUSE'. " +
                "It is false for the dominant path — McpToolContext.redactIfNeeded re-redacts every " +
                "MCP tool result under the CURRENT mode, so a switch to STRICT IS retroactive for " +
                "captured traffic. Scanner findings are the only forward-only case, and the clause " +
                "'$FORWARD_ONLY_CLAUSE' already states that WITH its scope. Retired 2026-08-28 by " +
                "phase 28 UAT test 2 (28-REVIEW-3.md WR-05). Tooltip was: $PRIVACY_MODE_TOOLTIP",
        )
    }

    /**
     * The recorded-findings clause — half two, and the one that says what the bound COSTS rather
     * than merely that a bound exists.
     */
    @Test
    fun theTooltipSaysAlreadyRecordedFindingsKeepTheValuesTheyWereBuiltWith() {
        assertTrue(
            PRIVACY_MODE_TOOLTIP.contains(RECORDED_FINDINGS_CLAUSE),
            "PRIVACY_MODE_TOOLTIP must contain the recorded-findings clause " +
                "'$RECORDED_FINDINGS_CLAUSE'. A tooltip saying only 'not retroactive' leaves an " +
                "operator to guess that a re-scan repairs the finding; it does not, because " +
                "AiScanCheck.consolidateIssues returns KEEP_EXISTING on a matching name and URL. " +
                "Tooltip was: $PRIVACY_MODE_TOOLTIP",
        )
    }

    /**
     * THE BOUND IS ADDED, NEVER SUBSTITUTED.
     *
     * Without this test the two assertions above could be satisfied by a tooltip that had thrown
     * away the sentence describing what the setting actually does — trading one operator-facing
     * defect for another and passing green while doing it.
     */
    @Test
    fun theTooltipStillStatesWhatTheSettingDoes() {
        assertTrue(
            PRIVACY_MODE_TOOLTIP.contains(PURPOSE_CLAUSE),
            "PRIVACY_MODE_TOOLTIP must still contain its purpose clause '$PURPOSE_CLAUSE'. The " +
                "bound is ADDED to the tooltip's job, not swapped in place of it: a caveat that " +
                "displaced the description would leave an operator knowing what the setting does " +
                "NOT do and not what it does. Tooltip was: $PRIVACY_MODE_TOOLTIP",
        )
    }

    /**
     * EXACTLY ONE OPERATOR-FACING SITE, AND IT REFERENCES THE CONSTANT.
     *
     * The clause assertions above measure a constant. They are only evidence about what an operator
     * READS if that constant is what the panel assigns — and if no SECOND assignment exists
     * elsewhere in main source carrying an un-pinned literal. This scan closes both gaps, and it is
     * a SOURCE scan rather than a symbol reference for that second reason: a symbol reference cannot
     * see a site that does not use the symbol, which is precisely the case worth catching.
     */
    @Test
    fun exactlyOnePrivacyModeTooltipAssignmentExistsInMainSourceAndItReferencesTheConstant() {
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the source walk reached ${files.size} .kt files under ${SourceRoots.PRODUCTION}, below the " +
                "floor of $MIN_EXPECTED_MAIN_FILES. The floor catches a walk that reached nothing " +
                "— a scan over an empty file list would satisfy the count below by measuring no " +
                "source at all — rather than tracking the file count.",
        )

        val matches = files.flatMap { file -> assignmentLinesIn(file).map { SourceRoots.relativePath(file) to it.trim() } }

        assertEquals(
            1,
            matches.size,
            "expected exactly ONE assignment to $TOOLTIP_ASSIGNMENT in ${SourceRoots.PRODUCTION}. Found " +
                "${matches.size}: $matches. A second site means an operator can be shown a tooltip " +
                "this file never sees, and the 'exactly one operator-facing surface' premise the " +
                "D-28-10 condition rests on is stale — every site would then need the bound clauses.",
        )

        val (path, line) = matches[0]

        assertTrue(
            line.contains(TOOLTIP_CONSTANT),
            "the single $TOOLTIP_ASSIGNMENT assignment (at $path) must reference $TOOLTIP_CONSTANT. " +
                "It reads: '$line'. If it assigns anything else, the string an operator reads and " +
                "the string the three assertions above measure are two objects, and they will drift.",
        )
        assertFalse(
            line.contains('"'),
            "the single $TOOLTIP_ASSIGNMENT assignment (at $path) must carry no string literal — " +
                "it reads: '$line'. An inline literal is how the tooltip becomes unpinnable again, " +
                "which is the exact state this plan found it in at HEAD.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Source-scan helpers. The walk and the relative paths come from SourceRoots, which covers both
    // production roots and renders paths with invariant separators (the WR-05 cross-platform fix).
    // ---------------------------------------------------------------------------------------------

    /**
     * Comment stripping is by LINE PREFIX — a line-comment marker, a KDoc continuation star, or a
     * block-comment opener — so the very comment written next to the assignment is not counted as a
     * second site, while a trailing comment on a real code line leaves that line visible.
     */
    private fun assignmentLinesIn(file: File): List<String> =
        file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }.filter { it.contains(TOOLTIP_ASSIGNMENT) }

    private companion object {
        // Measured well above this when the test was written. The floor catches a walk that reached
        // nothing; it is deliberately not a file count to track.
        const val MIN_EXPECTED_MAIN_FILES = 150

        /** The assignment this scan counts. Held as a constant so the needle is stated once. */
        const val TOOLTIP_ASSIGNMENT = "privacyMode.toolTipText"

        /** The name the single assignment must reference instead of a literal. */
        const val TOOLTIP_CONSTANT = "PRIVACY_MODE_TOOLTIP"
    }
}
