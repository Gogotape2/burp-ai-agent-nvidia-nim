package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * WHAT THIS IS FOR.
 *
 * Plan 27-08 authored a must-have that read: "No green test asserting that a cookie value SURVIVES a
 * redacting policy is committed anywhere under `src/`." Its own repository falsified it. Two green
 * `assertTrue` assertions pinning a fixture hostname as surviving the strongest privacy mode were
 * sitting in `mcp/tools/McpToolHelpersTest.kt` at the time the claim was written, and a third pinned
 * a cookie sentinel as surviving in `redact/CookieHeaderNameParityTest.kt`. Nothing swept, so
 * nothing contradicted the claim.
 *
 * A green test is the most authoritative statement a repository makes about intended behaviour. A
 * green assertion that a sensitive value SURVIVES `PrivacyMode.STRICT` or `PrivacyMode.BALANCED` is
 * therefore a leak documented as a feature — it teaches the next audit that the leak is expected.
 * Plan 27-05 prohibited exactly that artifact, and this phase committed two of them anyway. A fourth
 * prose claim would be the fourth iteration of the same failure. This file is the claim made
 * MECHANICAL: it scans `src/test/kotlin` and `src/fullTest/kotlin` (phase 29: the full flavor's
 * tests, so a pin moved there is still swept) on every CI run and fails on the next such pin — written
 * with a plain or a backtick-quoted name, under any modifier prefix, with or without a same-line
 * annotation. NOT written with an opening parenthesis somewhere other than its declaration line;
 * that shape is blind axis 9 below, and this sentence is scoped rather than deleted because a
 * SCOPED TRUE claim is the artifact this phase exists to produce.
 *
 * That scoping was earned, not chosen. Until plan 27-15 the sentence was unqualified while the gate
 * admitted ONE optional modifier and a word-character name only: MEASURED, 133 of 1781 declaration
 * lines under `src/test/kotlin` were invisible — 67 of them backtick-named `@Test` methods across 9
 * files, one of them in this very package — and a synthetic survival pin scored 1 of 6 declaration
 * shapes. The claim was wider than the control, inside the file written to stop exactly that.
 *
 * WHAT THE SCAN CAN SEE — read this before quoting the file as evidence.
 *
 * One shape, and only one: an `assertTrue` whose `.contains(` argument is in the MEASURED sentinel
 * vocabulary of [SENSITIVE_VALUE_VOCABULARY], appearing inside a test function whose body names one
 * of [REDACTING_POLICY_MARKERS].
 *
 * WHAT THE SCAN CANNOT SEE. THIRTEEN axes — the value of [STATED_BLIND_AXES] — named because a
 * tripwire quoted wider than the vocabulary it scans reproduces, one iteration smaller, the
 * register-wider-than-control defect this whole phase exists to repair. That count is
 * MACHINE-CHECKED against this very enumeration by
 * [theStatedBlindAxisCountMatchesTheEnumeration]: it can go stale only if a test goes red first,
 * which is the property the previous eleven-axis claim did not have when it went stale.
 *
 *  1. A survival pinned with `assertEquals` rather than `assertTrue`.
 *  2. A survival pinned with the `in` operator instead of `.contains(`.
 *  3. A survival pinned with a regex find.
 *  4. A survival pinned with `assertNotNull`.
 *  5. A survival asserted through a helper defined in ANOTHER file, so neither token is in the body.
 *  6. A sensitive value that does not follow the measured naming convention and is not in
 *     [HOST_LITERALS].
 *  7. Anything above the unit suite — an integration run, a manual probe, a shipped log.
 *  8. A survival pin split across TWO functions: the policy marker in one, the assertion in another.
 *     The ISOLATION UNIT IS A WHOLE `fun` BODY, BLANK LINES INCLUDED, from the declaration line to
 *     the first non-blank line at or above its indent (in Kotlin, the closing brace). Function-scoped
 *     isolation is the chosen bound and this is what it costs.
 *  9. A survival pin on a declaration line whose OPENING PARENTHESIS does not follow the identifier
 *     on that same line. [FUNCTION_DECLARATION] requires it there, and [detect] returns early on a
 *     non-matching declaration line, so such a body is invisible ENTIRELY. Two shapes, both MEASURED
 *     on this tree after plan 27-15's widening: an EXTENSION RECEIVER (`private fun
 *     String.indentWidth()`) — 3 declarations, one of them in THIS file — and a MULTI-LINE SIGNATURE
 *     whose parenthesis sits on the next line, 0 today. This axis is the PRICE OF THAT WIDENING and
 *     it is named in the same change that created it, which is the discipline round 4 failed.
 * 10. A survival pin combined with a NEGATED containment inside ONE compound `assertTrue`.
 *     [assertsPresenceAt] computes negation from the `assertTrue(` opener to the containment under
 *     test, so where the FIRST operand is negated every later containment in the same assertion
 *     inherits that negation. `assertTrue(!a.contains(x) && b.contains(sentinel))` is therefore
 *     invisible. Unlike axes 11-13 this is an OVER-FIRE of a rule rather than the price of one.
 *     THE FIX, WRITTEN DOWN SO THE NEXT ENGINEER MEETS IT RATHER THAN RE-DERIVING IT: scope the
 *     negation test to the operand IMMEDIATELY PRECEDING the call, bounded by the nearest `&&`,
 *     `||` or comma, instead of to the whole span back to the opener. DELIBERATELY NOT APPLIED in
 *     round 5: the negation rule is load-bearing for 1 measured live hit and changing it without its
 *     own flip-pair fixture is how a detector gets quietly disarmed — the failure mode
 *     [theBenignExclusionCannotSwallowARealSentinel] exists to prevent for the other exclusion.
 *
 * The remaining three are the price of the three exclusions built into the detector. Each is stated
 * as a COST, not as a feature:
 *
 * 11. A survival pin whose text lives INSIDE a triple-quoted raw string. The FILE WALK skips those
 *     lines. That skip is not tidiness and it is not a self-file exclusion: EVERY fixture in this
 *     file is a verbatim copy of a real test function and therefore CARRIES ITS OWN `fun`
 *     DECLARATION LINE — that line is exactly what the isolation needs in order to isolate the
 *     fixture at all — and a line-based walk matches such a line inside a triple-quoted literal
 *     precisely as it matches one in code. Holding the fixtures at companion level does NOT prevent
 *     this; a line-based walk reads CONTENTS, not declarations. Without the skip this file flags
 *     ITSELF. The skip applies to every file the walk touches, and it is asserted non-vacuous in
 *     both directions by [theSweepFileItselfYieldsNoHits] and
 *     [theRawStringSkipIsWhyTheSelfScanIsClean] — and, since plan 27-15, in the FLAGGING direction
 *     too by [theWalkPreservesRealCodeWhileSkippingRawStringInteriors], which is the one that
 *     catches the skip growing to swallow real code.
 * 12. A survival pin positioned textually ABOVE the line that first names the policy. The POSITION
 *     RULE reads those as PRE-REDACTION FIXTURE GUARDS, because nothing has been redacted yet at
 *     that point in the body.
 * 13. A genuinely sensitive value reached through the one accessor named in [BENIGN_ACCESSORS].
 *
 * THE THREE EXCLUSIONS ARE CONSTRUCTED INTO THE DETECTOR, NEVER INTO [ALLOWLIST]. RE-MEASURED at
 * execution time in plan 27-15, running this detector — as WIDENED by that plan — over the 151 `.kt`
 * files of `src/test/kotlin`: the vocabulary WITHOUT the three exclusions reports 9 hits, every one
 * of them a LEGITIMATE shape — 7 benign-control assertions, 1 pre-redaction fixture guard, 1 negated
 * containment. WITH the three exclusions it reports 0. Run against the PRE-ROUND contents of the two
 * files that carried the pins, WITH the exclusions, it reports EXACTLY 3, and those 3 ARE the two
 * host pins and the underscore pin, under those same three identifiers.
 *
 * 9 / 7 / 1 / 1 / 0 / 3 are the numbers BEFORE the widening as well as after it. That equality is
 * the load-bearing part of the measurement, not a footnote: widening the declaration gate to 133
 * more declaration lines surfaced NOTHING new, so the widening bought scope without buying noise,
 * and nothing was narrowed to keep the hit set empty. Separately measured and stated because it is
 * easy to misread the 9: the raw occurrence count over the same population is 36, of which 27 are
 * `assertFalse` containments that are not candidates under ANY reading — the `assertTrue`
 * requirement is not one of the three exclusions, and counting them into the 9 would inflate the
 * exclusions' apparent cost by a factor of four.
 *
 * The 7 is stated as MEASURED HERE and not as inherited: plan 27-12 projected 5, which was the count
 * before plan 27-11 added two more JSON-string-open probes that each carry a benign-control
 * assertion. Re-measured again after plan 27-14, which added tests but no eighth benign-control
 * function: still 7, in 7 distinct live functions, all in `SerializedEmissionRedactionTest`. The
 * number is written down at what it actually is, because a stated bound wider or narrower than the
 * control it describes is the exact defect this phase exists to repair.
 *
 * Growing [ALLOWLIST] instead, or narrowing the vocabulary, is forbidden: both make an inconvenient
 * hit set empty without making the repository any safer.
 *
 * DURABLE CHECK versus ONE-TIME EVIDENCE, stated so the two are never confused. The in-file fixtures
 * below are the DURABLE check: they run on every CI run and they are what survives this phase. The
 * demonstration that this detector reports exactly three hits against the PRE-ROUND file contents
 * retrieved from git history is EXECUTION-TIME evidence, recorded in `27-12-SUMMARY.md` with its SHA,
 * its command and its raw output. It is NOT re-run by CI, deliberately: a `@Test` that shelled out to
 * git would make CI fail on repository history rather than on the code under test.
 *
 * This file is a TRIPWIRE OVER A MEASURED VOCABULARY, not a proof of coverage. A reader who quotes
 * it as proof of coverage reproduces the defect this phase exists to repair.
 */
class RedactingPolicySurvivalSweepTest {
    // ── the durable claim ─────────────────────────────────────────────────────────────────

    @Test
    fun noGreenTestAssertsASensitiveValueSurvivesARedactingPolicy() {
        val hits = SourceRoots.testKotlinFiles().flatMap { detect(SourceRoots.relativePath(it), fileWalk(it)) }
        val identifiers = hits.map { it.identifier }.toSet()

        assertEquals(
            ALLOWLIST.keys,
            identifiers,
            "the set of tests asserting that a sensitive value SURVIVES a redacting policy has " +
                "changed.\n" +
                "  NEW (delete the assertion, or re-point it at the privacy mode where pass-through " +
                "is the CORRECT behaviour — do NOT add an ALLOWLIST key to make this green): " +
                "${identifiers - ALLOWLIST.keys}\n" +
                "  STALE (allowlisted here but no longer matched — remove the entry so the allowlist " +
                "cannot accumulate dead keys): ${ALLOWLIST.keys - identifiers}\n" +
                "  Full hits: $hits",
        )
    }

    // ── the self-scan, and the counterpart that makes it falsifiable ──────────────────────

    @Test
    fun theSweepFileItselfYieldsNoHits() {
        val self = SourceRoots.testFile(SELF_PATH)
        val hits = detect(SELF_PATH, fileWalk(self))

        assertTrue(
            hits.isEmpty(),
            "this file flagged ITSELF: $hits. A self-hit means a fixture leaked OUT of a " +
                "triple-quoted literal and into real code. The fix is to move the fixture back into " +
                "the companion as a raw string — NEVER to add a self-file exclusion, which would " +
                "make the detector narrower than its stated scope.",
        )
    }

    @Test
    fun theRawStringSkipIsWhyTheSelfScanIsClean() {
        val self = SourceRoots.testFile(SELF_PATH)
        val unskipped = detect(SELF_PATH, self.readLines())

        assertTrue(
            unskipped.isNotEmpty(),
            "the detector run over THIS FILE WITHOUT the raw-string skip found nothing. Either the " +
                "skip is doing nothing (and the clean self-scan is an accident), or the detector has " +
                "quietly stopped matching (and every other assertion here is vacuous). A green " +
                "self-scan with no such counterpart is unfalsifiable.",
        )
        assertTrue(
            unskipped.size >= MIN_EXPECTED_UNSKIPPED_SELF_HITS,
            "expected at least $MIN_EXPECTED_UNSKIPPED_SELF_HITS unskipped self-hits from the " +
                "positive fixtures; found ${unskipped.size}: $unskipped",
        )
    }

    // ── the walk and the detector, bound together in the FLAGGING direction ───────────────

    @Test
    fun theWalkPreservesRealCodeWhileSkippingRawStringInteriors() {
        val hits = detect(FIXTURE_ID, dropRawStringInteriors(FIXTURE_ID, WALK_COMPOSITION_FIXTURE.lines()))

        assertEquals(
            1,
            hits.size,
            "the walk must BLANK the raw-string half of this fixture AND leave the real-code half " +
                "scannable. The two failures this distinguishes are not symmetric:\n" +
                "  TWO hits — the raw-string skip has stopped working, and this file will flag its " +
                "own fixtures. Loud, and self-correcting.\n" +
                "  ZERO hits — the walk has started BLANKING REAL CODE. The tree scan then returns " +
                "an empty hit set for the whole repository and every other test in this file stays " +
                "green, so the sweep reports SAFE while seeing nothing. That is the failure this " +
                "test exists for, and until plan 27-15 nothing asserted against it: every proof the " +
                "detector could produce a hit bypassed the walk, and the ONE path that used the " +
                "walk expected EMPTY. The file's own comment named this 'the dangerous direction' " +
                "for a full round without gating it. Hits: $hits",
        )
        assertEquals(
            REAL_CODE_PIN_IDENTIFIER,
            hits.single().identifier.substringAfter('#'),
            "one hit is not enough — it must be the REAL-CODE half. A single hit carrying the " +
                "raw-string half's identifier would mean the walk has inverted: blanking the code " +
                "and preserving the fixture. Hits: $hits",
        )
    }

    @Test
    fun theWalkFailsLoudlyWhenAFileEndsInsideARawString() {
        val thrown =
            assertThrows(AssertionError::class.java) {
                dropRawStringInteriors(FIXTURE_ID, UNBALANCED_WALK_FIXTURE.lines())
            }

        assertTrue(
            thrown.message.orEmpty().contains(FIXTURE_ID),
            "the walk must NAME the source it could not balance, or the error cannot be acted on: " +
                "the whole point is to identify WHICH file had its tail blanked. Message: " +
                "${thrown.message}",
        )
    }

    @Test
    fun aTrailingCommentMentioningATripleQuoteDoesNotToggleTheRawStringState() {
        val walked = dropRawStringInteriors(FIXTURE_ID, TRAILING_COMMENT_WALK_FIXTURE.lines())

        assertTrue(
            walked.any { it.contains(TRAILING_COMMENT_CODE_LINE) },
            "the line carrying the trailing comment is REAL CODE and must not be blanked. Reaching " +
                "this assertion at all means the walk did not THROW, which is the first half of the " +
                "claim: this fixture is BALANCED — its only triple quote sits inside a comment — so " +
                "an unbalanced-file error here would be the walk toggling its state from a comment " +
                "and then blaming the file for it. Walked: $walked",
        )
        val hits = detect(FIXTURE_ID, walked)
        assertEquals(
            1,
            hits.size,
            "the walk must leave everything BELOW the trailing comment scannable. ZERO hits means " +
                "the comment's triple quote toggled the state and the rest of the fixture was " +
                "blanked — the silent direction, in which the tree scan reports SAFE while seeing " +
                "nothing. The in-code rule has always said a COMMENT never opens or closes a raw " +
                "string; until the 27-REVIEW-3 WR-02 correction only the WHOLE-LINE form was " +
                "implemented. Hits: $hits",
        )
        assertEquals(
            TRAILING_COMMENT_PIN_IDENTIFIER,
            hits.single().identifier.substringAfter('#'),
            "one hit is not enough — it must be the pin BELOW the trailing comment. Hits: $hits",
        )
    }

    // ── the detector is proven live, fixture by fixture ───────────────────────────────────

    @Test
    fun everyVocabularyEntryIsProvenLiveAgainstItsOwnPositiveFixture() {
        assertEquals(
            SENSITIVE_VALUE_VOCABULARY.size,
            VOCABULARY_FIXTURES.size,
            "every vocabulary entry needs its own positive fixture, or an entry that has stopped " +
                "matching can hide in the list and make the whole scan vacuously clean",
        )

        VOCABULARY_FIXTURES.forEachIndexed { index, fixture ->
            val hits = detect(FIXTURE_ID, fixture.lines())
            assertTrue(
                hits.any { it.vocabularyEntry == index },
                "vocabulary entry $index (/${SENSITIVE_VALUE_VOCABULARY[index].pattern}/) matched no " +
                    "hit in its own positive fixture — it can no longer detect the form it exists to " +
                    "detect. Hits found: $hits",
            )
        }
    }

    @Test
    fun theSkipHasNotDisarmedTheDetector() {
        // The file walk SKIPS this text; the detector, handed the SAME text directly, must still
        // flag it. A skip that had silenced the detector everywhere would pass the self-scan above
        // and fail here, which is the entire point of asserting both directions.
        VOCABULARY_FIXTURES.forEach { fixture ->
            assertTrue(
                detect(FIXTURE_ID, fixture.lines()).isNotEmpty(),
                "a positive fixture the file walk skips was NOT flagged when handed straight to the " +
                    "detector: the raw-string skip has disarmed the detector rather than scoped it",
            )
        }
    }

    // ── the two host pins removed this round ──────────────────────────────────────────────

    @Test
    fun theTwoHostPinsRemovedThisRoundAreFlagged() {
        val hits = detect(FIXTURE_ID, HOST_PIN_FIXTURE.lines())

        assertEquals(
            2,
            hits.size,
            "the pre-round copy of the end-to-end test carried exactly TWO survival pins on the " +
                "fixture host — one on the serialized raw-message shape, one on the header-map " +
                "shape. Found: $hits",
        )
        assertTrue(
            hits.all { it.vocabularyEntry == HOST_LITERAL_ENTRY },
            "both hits must come from the host-literal vocabulary entry, not from another entry " +
                "matching by accident. Found: $hits",
        )

        val body = isolatedBodyOf(HOST_PIN_FIXTURE)
        assertTrue(
            body.count { it.isBlank() } >= 2,
            "the isolated body carries ${body.count { it.isBlank() }} blank lines — the marker and " +
                "the pins sit on opposite sides of several, so a blank-line-terminating isolation " +
                "would return a stub containing neither pin",
        )
        assertTrue(
            REDACTING_POLICY_MARKERS.any { marker -> body.any { it.contains(marker) } },
            "the isolated body lost the redacting-policy marker, so the body was truncated",
        )
        assertEquals(
            2,
            body.count { line -> HOST_LITERALS.any { line.contains(it) && line.contains(".contains(") } },
            "the isolated body must still carry BOTH host pins — the two tokens the naive isolation " +
                "separates",
        )
    }

    // ── the blank-line hazard, machine-checked ────────────────────────────────────────────

    @Test
    fun theBlankLineHazardFixtureIsIsolatedWholeIncludingItsBlankLines() {
        val body = isolatedBodyOf(BLANK_LINE_HAZARD_FIXTURE)

        assertTrue(
            body.count { it.isBlank() } >= 2,
            "the isolated body must CONTAIN at least two blank lines, proving the walk CONSUMED " +
                "them rather than stopping at the first. Found ${body.count { it.isBlank() }} in a " +
                "body of ${body.size} lines. If this is 0, the walk was simplified back to a " +
                "blank-line-terminating shape and this whole file is silently narrower than its " +
                "stated bound.",
        )
    }

    @Test
    fun theBlankLineHazardFixtureCarriesBothTokensAndIsFlagged() {
        val body = isolatedBodyOf(BLANK_LINE_HAZARD_FIXTURE)

        assertTrue(
            REDACTING_POLICY_MARKERS.any { marker -> body.any { it.contains(marker) } },
            "the isolated body must contain the redacting-policy marker, which in this fixture sits " +
                "TWO blank lines below the declaration",
        )
        assertTrue(
            body.any { it.contains(".contains(") },
            "the isolated body must contain the flagged containment call, which sits below the " +
                "marker again",
        )
        assertTrue(
            detect(FIXTURE_ID, BLANK_LINE_HAZARD_FIXTURE.lines()).isNotEmpty(),
            "the blank-line hazard fixture must be FLAGGED. It is a verbatim copy of a real survival " +
                "pin this round removed; if it is clean, the detector no longer finds the artifact " +
                "it was written for.",
        )
    }

    // ── the benign exclusion has a floor ──────────────────────────────────────────────────

    @Test
    fun theBenignExclusionCannotSwallowARealSentinel() {
        assertTrue(
            detect(FIXTURE_ID, ANTI_SWALLOW_FIXTURE.lines()).isNotEmpty(),
            "the anti-swallow fixture — a real absence assertion with ONLY its verb flipped, so it " +
                "now asserts a real cookie sentinel SURVIVES — was not flagged. That means the " +
                "benign exclusion is subtracting the enum-accessor FORM rather than the ONE named " +
                "constant it is scoped to, and every enum-accessor survival pin is now invisible.",
        )
        assertTrue(
            detect(FIXTURE_ID, NEGATIVE_ASSERT_FALSE_FIXTURE.lines()).isEmpty(),
            "the same block UNFLIPPED is an absence assertion and must stay clean — the pair is what " +
                "proves the flip, and not something else, is what made it flag",
        )
    }

    // ── the six legitimate shapes that must stay clean ────────────────────────────────────

    @Test
    fun noLegitimateShapeOnThisTreeIsFlagged() {
        NEGATIVE_FIXTURES.forEach { (label, fixture) ->
            assertTrue(
                detect(FIXTURE_ID, fixture.lines()).isEmpty(),
                "the legitimate shape '$label' was FLAGGED. It is taken from the real tree and it is " +
                    "not a survival pin. Fix the detector — do NOT add an ALLOWLIST key, which would " +
                    "silence a shape the detector should never have claimed. Hits: " +
                    "${detect(FIXTURE_ID, fixture.lines())}",
            )
        }
        assertEquals(
            EXPECTED_NEGATIVE_FIXTURES,
            NEGATIVE_FIXTURES.size,
            "the six legitimate shapes measured on this tree are the floor of this test; a fixture " +
                "removed from the list is coverage removed without a decision",
        )
    }

    // ── the declaration gate everything else is downstream of ─────────────────────────────

    @Test
    fun everyDeclarationShapeInUseInThisRepositoryIsVisibleToTheSweep() {
        // Driven through `detect` DIRECTLY, like every other positive fixture here, because the
        // fixture lives inside a raw string the walk exists to skip.
        val hits = detect(FIXTURE_ID, DECLARATION_SHAPE_FIXTURE.lines())

        assertEquals(
            EXPECTED_DECLARATION_SHAPE_HITS,
            hits.size,
            "a survival pin is invisible to this sweep unless its DECLARATION LINE matches " +
                "FUNCTION_DECLARATION: detect() returns early on a non-matching declaration, so an " +
                "unmatched declaration hides its ENTIRE body, not merely its name. MEASURED on this " +
                "tree before plan 27-15 widened the regex: 133 of 1781 declaration lines invisible " +
                "(136 of 1784 counting extension receivers, which is the population 27-REVIEW-2 " +
                "CR-01 reported), 67 of them backtick-named @Test methods across 9 files including " +
                "redact/SecretTripwireHooksTest.kt, and 61 of them `override fun`. This fixture " +
                "scored 1 of 6 then. If it scores less than 6 now, the gate has narrowed back and " +
                "that population is invisible again. Hits: $hits",
        )
        assertEquals(
            DECLARATION_SHAPE_IDENTIFIERS,
            hits.map { it.identifier.substringAfter('#') }.toSet(),
            "the hit COUNT can be right while every identifier is wrong. The widened regex carries " +
                "TWO name groups — group 1 plain, group 2 backtick-quoted — and reading the wrong " +
                "one yields empty identifiers for every plain-named hit, which would silently make " +
                "the allowlist-key comparison in " +
                "noGreenTestAssertsASensitiveValueSurvivesARedactingPolicy compare blanks. Hits: $hits",
        )
    }

    // ── the stated bound, read back out of this file's own source ─────────────────────────

    @Test
    fun theStatedBlindAxisCountMatchesTheEnumeration() {
        val source = SourceRoots.testFile(SELF_PATH).readLines()
        val kdocOpensAt = source.indexOfFirst { it.trimStart().startsWith("/**") }
        val classAt = source.indexOfFirst { it.startsWith("class $SELF_CLASS") }

        assertTrue(
            kdocOpensAt in 0 until classAt,
            "could not isolate the class KDoc region: opens at $kdocOpensAt, class declared at " +
                "$classAt. The region bound is what makes this test read the ENUMERATION rather " +
                "than every numbered list in the file.",
        )

        val enumerated = source.subList(kdocOpensAt, classAt).count { AXIS_ENTRY.containsMatchIn(it) }

        assertEquals(
            STATED_BLIND_AXES,
            enumerated,
            "the class KDoc states its bound as $STATED_BLIND_AXES blind axes and enumerates " +
                "$enumerated. A stated bound that does not match the enumeration it describes is " +
                "the EXACT defect this phase exists to repair, committed four times: the sweep's " +
                "own eleven-axis claim went stale while `26-SECURITY.md` clause (vi) cited it as " +
                "this check's stated bound, and nothing was red. This test is why that can no " +
                "longer happen silently — the number in the register can go stale only if this " +
                "goes red first. Fix whichever of the two is wrong; do NOT adjust the constant to " +
                "match a miscounted enumeration.",
        )
    }

    /**
     * The SECOND of clause (vi)'s three numbers, machine-checked for the first time.
     *
     * `26-SECURITY.md` standing-rule clause (vi) cites this class BY TEST COUNT. That number was
     * transcribed by hand and it went stale inside the round that wrote it: `fb7cbd3` added a
     * sixteenth `@Test` and touched no record, so the clause that prohibits a stated bound wider
     * than its control stated a control this file falsified. The axis count beside it — the ONE
     * number in the clause that was machine-checked — did not drift. That contrast is the whole
     * argument for this test.
     *
     * It counts over [fileWalk] rather than over the raw lines DELIBERATELY: the raw file carries a
     * seventeenth `@Test` inside [DECLARATION_SHAPE_FIXTURE], which is fixture text and not a method
     * this class runs. The walk blanks raw-string interiors, so the count is over real code — and it
     * therefore also goes red if the walk ever starts blanking real code, which is the silent
     * direction this file exists to make loud.
     */
    @Test
    fun theStatedTestMethodCountMatchesThisFilesOwnDeclarations() {
        val declared = fileWalk(SourceRoots.testFile(SELF_PATH)).count { TEST_ANNOTATION.containsMatchIn(it) }

        assertEquals(
            STATED_TEST_METHODS,
            declared,
            "this class declares $declared `@Test` methods and states $STATED_TEST_METHODS. " +
                "`26-SECURITY.md` standing-rule clause (vi) cites that stated number as this " +
                "check's size, so a change to this file that does not move the constant makes the " +
                "REGISTER false — which is exactly what happened at fb7cbd3, silently, inside the " +
                "round that added the machine check for the axis count next to it. Update BOTH " +
                "this constant and clause (vi); do NOT adjust the constant alone.",
        )
    }

    /**
     * The THIRD of clause (vi)'s three numbers: the unskipped self-hit count, pinned EXACTLY.
     *
     * [theRawStringSkipIsWhyTheSelfScanIsClean] asserts the same population against
     * [MIN_EXPECTED_UNSKIPPED_SELF_HITS], and that FLOOR is deliberate and stays — it is there to
     * catch a detector that has been silently disarmed, not to track a count. A floor cannot keep a
     * register sentence honest, though: clause (vi) quotes the EXACT number as the evidence that
     * this file's clean self-scan is falsifiable, and `fb7cbd3`'s new raw-string fixture moved it by
     * one while every assertion in this class stayed green.
     *
     * So the count is pinned here as well as floored there, and the two assertions are kept in
     * separate tests on purpose: they answer different questions and a reader who trips one should
     * not have to work out which.
     */
    @Test
    fun theStatedUnskippedSelfHitCountMatchesThisFile() {
        val unskipped = detect(SELF_PATH, SourceRoots.testFile(SELF_PATH).readLines())

        assertEquals(
            STATED_UNSKIPPED_SELF_HITS,
            unskipped.size,
            "the detector run over THIS FILE WITHOUT the raw-string skip found ${unskipped.size} " +
                "hits; $STATED_UNSKIPPED_SELF_HITS is what this file and `26-SECURITY.md` " +
                "standing-rule clause (vi) both state. UP means a fixture gained a survival pin — " +
                "re-count it and move BOTH numbers. DOWN means a positive fixture stopped being " +
                "detected, which makes the clean self-scan above an accident rather than a " +
                "measurement. Either way the register sentence is now false until it is amended in " +
                "the SAME change. Hits: $unskipped",
        )
    }

    // ── non-vacuity of the walk itself ────────────────────────────────────────────────────

    @Test
    fun theTreeWalkIsNonVacuous() {
        // A repository-state test that goes green when it cannot find the repository is worse than
        // the grep it replaces. The root resolver throws rather than skips; this asserts the walk it
        // returns actually reached the tree.
        val files = SourceRoots.testKotlinFiles()

        assertTrue(
            files.size >= MIN_EXPECTED_TEST_FILES,
            "the walk found only ${files.size} .kt files under ${SourceRoots.TESTS} — the scan is not " +
                "reaching the repository, so its other assertions prove nothing",
        )
        assertTrue(
            files.any { SourceRoots.relativePath(it) == SELF_PATH },
            "the walk did not reach THIS file. The self-scan is only meaningful because this file is " +
                "walked like every other; there is no self-exclusion and there must never be one.",
        )
    }

    // ── the file walk: a path becomes lines ───────────────────────────────────────────────

    /**
     * Reads a file and BLANKS every line whose triple-quote state was INSIDE at the START of the
     * line, BEFORE any function-declaration matching happens.
     *
     * Blanked rather than dropped, so line numbering is preserved. The opening `val X =` line and
     * the line carrying the opening `"""` keep their content (their state at line start is OUTSIDE);
     * the literal's contents and its closing line do not.
     *
     * This is the one narrowing that makes the self-scan clean, and it is declared in the class KDoc
     * as blind axis 11 rather than sold as a feature.
     */
    private fun fileWalk(file: File): List<String> = dropRawStringInteriors(SourceRoots.relativePath(file), file.readLines())

    private fun dropRawStringInteriors(
        sourceId: String,
        lines: List<String>,
    ): List<String> {
        var inside = false
        val walked =
            lines.map { line ->
                val startedInside = inside
                // A COMMENT NEVER OPENS OR CLOSES A RAW STRING, so it must not toggle the state —
                // and as of the 27-REVIEW-3 WR-02 correction that rule covers a TRAILING comment as
                // well as a whole-line one. It did not before: [isCommentOnly] only recognises a line
                // whose FIRST non-space characters are `//`, `*` or `/*`, so `val x = 1 // … """ …`
                // toggled the state from inside a comment and inverted the walk for every line below
                // it. MEASURED on a one-line fixture: the trailing form ended INSIDE and the same
                // text written as a whole-line comment did not. Latent rather than live — no file in
                // `src/test/kotlin` carries that shape today — but since plan 27-15 made the
                // unbalanced case THROW, the next developer to write one would have taken two tests
                // red with a message telling them to balance a quote in an already-balanced file.
                //
                // TWO BOUNDS ON THE STRIP, both deliberate and both MEASURED rather than assumed.
                // It is applied only when the line STARTS OUTSIDE a raw string: inside one, `//` is
                // CONTENT, and stripping it would swallow a closing quote and manufacture the very
                // unbalanced state this walk throws on — the splice lines of the fixtures below are
                // exactly that shape. And [trailingCommentStripped] is a three-state scan rather than
                // a `substringBefore`, because a `//` inside a STRING is not a comment either: the
                // naive cut takes `ui/ChatPanelToolGateTest.kt` unbalanced on this tree today, which
                // that function's KDoc records with the offending line.
                //
                // This is not tidiness. MEASURED on this very file: a KDoc above quotes a
                // bare triple quote while explaining what this walk does, which is an ODD toggle,
                // and it INVERTED the state for every line below it — the fixtures read as code and
                // the code read as fixture. The self-scan caught it loudly.
                //
                // THE DANGEROUS DIRECTION IS THE OTHER ONE, and as of plan 27-15 it is ASSERTED
                // rather than merely named. An odd toggle in prose can blank REAL code, and a tree
                // scan over blanked code returns zero with every other test in this file still
                // green — a silently vacuous pass, which is worse than a red one. Two tests stand
                // against it now:
                //   - [theWalkPreservesRealCodeWhileSkippingRawStringInteriors] drives the walk and
                //     the detector as ONE composition and demands EXACTLY ONE hit. Zero means the
                //     walk has started blanking real code; two means the skip has stopped working.
                //     Until 27-15 every proof the detector could produce a hit bypassed the walk,
                //     and the only path that used the walk expected EMPTY.
                //   - [theWalkFailsLoudlyWhenAFileEndsInsideARawString] covers the case no fixture
                //     can reach from inside: a scanned file with an unbalanced quote, whose whole
                //     tail this walk would otherwise blank and report as clean.
                // The bare triple quote in the KDoc above is deliberately left in place, so this
                // rule stays exercised by the file itself rather than by nothing.
                val scannable = if (startedInside) line else trailingCommentStripped(line)
                if (!isCommentOnly(line)) {
                    var index = 0
                    while (index <= scannable.length - TRIPLE_QUOTE.length) {
                        if (scannable.regionMatches(index, TRIPLE_QUOTE, 0, TRIPLE_QUOTE.length)) {
                            inside = !inside
                            index += TRIPLE_QUOTE.length
                        } else {
                            index++
                        }
                    }
                }
                if (startedInside) "" else line
            }
        if (inside) {
            throw AssertionError(
                "unbalanced triple quotes in $sourceId: this source ENDS INSIDE a raw string, so " +
                    "everything below the unbalanced quote was BLANKED by this walk. Any survival " +
                    "pin in that tail was invisible, and this file's contribution to the tree scan " +
                    "was a vacuous zero that no hit count could have revealed. Fix the FILE — " +
                    "balance the quote — not this check, and do not exclude the file from the walk.",
            )
        }
        return walked
    }

    // ── the detector: lines become hits ───────────────────────────────────────────────────

    /**
     * Deliberately a SEPARATE entry point from [fileWalk]. The positive-fixture tests drive this
     * function DIRECTLY on the same text the walk skips; the tree scan and the self-scan go through
     * the walk first. That separation is what makes the raw-string skip checkable in both
     * directions.
     */
    private fun detect(
        sourceId: String,
        lines: List<String>,
    ): List<Hit> {
        val hits = mutableListOf<Hit>()
        lines.forEachIndexed { index, line ->
            val declaration = FUNCTION_DECLARATION.find(line) ?: return@forEachIndexed
            // Comment lines are dropped AFTER isolation, never before it: dropping them first would
            // shorten bodies and move where the walk terminates, which is a second way to get a
            // silently truncated body.
            val body = functionBodyAt(lines, index).filterNot { isCommentOnly(it) }
            val normalised = body.joinToString(" ").replace(WHITESPACE_RUN, " ")
            val markerAt =
                REDACTING_POLICY_MARKERS
                    .map { normalised.indexOf(it) }
                    .filter { it >= 0 }
                    .minOrNull() ?: return@forEachIndexed

            // Group 1 is a plain identifier, group 2 a backtick-quoted one; exactly one is non-empty
            // per match. Reading a single fixed index yields an empty identifier for the other
            // spelling, which would make the allowlist-key comparison in
            // [noGreenTestAssertsASensitiveValueSurvivesARedactingPolicy] compare blanks without
            // failing anything. [DECLARATION_SHAPE_IDENTIFIERS] is the floor under this line.
            val identifier = declaration.groupValues[1].ifEmpty { declaration.groupValues[2] }

            hits +=
                candidatesIn(normalised, markerAt).mapNotNull { argument ->
                    vocabularyEntryFor(argument)?.let { entry ->
                        Hit("$sourceId#$identifier", argument, entry)
                    }
                }
        }
        return hits
    }

    /**
     * The `.contains(` arguments in a normalised body that are asserted PRESENT by an `assertTrue`,
     * after the point at which the body first names a redacting policy.
     *
     * Two of the three constructed exclusions live here. THE POSITION RULE: an occurrence before the
     * first policy marker is a PRE-REDACTION FIXTURE GUARD asserting the value is present in the
     * INPUT — which is what makes the later absence assertion non-vacuous — so it is not a candidate.
     * THE NEGATION RULE: `assertTrue(!x.contains(v))` is an ABSENCE assertion wearing the wrong verb.
     */
    private fun candidatesIn(
        normalised: String,
        firstMarkerAt: Int,
    ): List<String> =
        containsOccurrencesIn(normalised)
            // THE POSITION RULE.
            .filter { it >= firstMarkerAt }
            // The `assertTrue` requirement, and THE NEGATION RULE.
            .filter { assertsPresenceAt(normalised, it) }
            .mapNotNull { argumentAt(normalised, it + CONTAINS_CALL.length) }

    /** Every index at which a `.contains(` call opens in the normalised body. */
    private fun containsOccurrencesIn(normalised: String): List<Int> {
        val occurrences = mutableListOf<Int>()
        var from = 0
        while (true) {
            val at = normalised.indexOf(CONTAINS_CALL, from)
            if (at < 0) break
            occurrences += at
            from = at + CONTAINS_CALL.length
        }
        return occurrences
    }

    /**
     * Whether the `.contains(` at [at] is asserted PRESENT: the nearest preceding assertion opener is
     * an `assertTrue(` rather than an `assertFalse(`, and the receiver between that opener and the
     * call is not negated.
     */
    private fun assertsPresenceAt(
        normalised: String,
        at: Int,
    ): Boolean {
        val trueOpener = normalised.lastIndexOf(ASSERT_TRUE, at)
        val falseOpener = normalised.lastIndexOf(ASSERT_FALSE, at)
        val negated =
            trueOpener >= 0 &&
                normalised.substring(trueOpener + ASSERT_TRUE.length, at).trimStart().startsWith("!")
        return trueOpener >= 0 && falseOpener < trueOpener && !negated
    }

    /** The text between a `.contains(` and its MATCHING close parenthesis, found by counting. */
    private fun argumentAt(
        normalised: String,
        start: Int,
    ): String? {
        var depth = 1
        var index = start
        while (index < normalised.length) {
            when (normalised[index]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return normalised.substring(start, index).trim()
                }
            }
            index++
        }
        return null
    }

    /**
     * The vocabulary entry an argument belongs to, or null.
     *
     * The third constructed exclusion lives here. [BENIGN_ACCESSORS] is SUBTRACTED from the
     * enum-accessor form: asserting that the negative-control constant survives is the whole point of
     * a negative control — it proves a pass was not produced by blanket destruction of the payload.
     * It subtracts ONE NAMED CONSTANT and never the form itself, which [ANTI_SWALLOW_FIXTURE]
     * asserts.
     */
    private fun vocabularyEntryFor(argument: String): Int? {
        val index = SENSITIVE_VALUE_VOCABULARY.indexOfFirst { it.matches(argument) }
        val benign = index == ENUM_ACCESSOR_ENTRY && argument.removeSuffix(ACCESSOR_SUFFIX) in BENIGN_ACCESSORS
        return index.takeIf { it >= 0 && !benign }
    }

    // ── the function-body isolation ───────────────────────────────────────────────────────

    /**
     * The declaration line plus its WHOLE body, BLANK LINES INCLUDED, terminating at the first line
     * that is BOTH non-blank AND indented at or above the declaration. In Kotlin that line is the
     * function's own closing brace.
     *
     * Written out rather than reused from `LogicalLineBoundaryScopeTest.declarationBlockOf`, whose
     * `takeWhile` STOPS AT THE FIRST BLANK LINE. That termination is correct for a regex-fragment
     * property, which has no blank lines, and measurably WRONG for a test function body, which is
     * mostly blank-line-separated paragraphs: on all three artifacts this sweep was written to find,
     * the redacting-policy marker and the pin sit on OPPOSITE SIDES of at least one blank line, so a
     * blank-line-terminating isolation gives a hit set of ZERO with every test still green.
     * [BLANK_LINE_HAZARD_FIXTURE] machine-checks that this has not been simplified back.
     */
    private fun functionBodyAt(
        lines: List<String>,
        declarationIndex: Int,
    ): List<String> {
        val declarationIndent = lines[declarationIndex].indentWidth()
        val body = mutableListOf(lines[declarationIndex])
        for (index in declarationIndex + 1 until lines.size) {
            val line = lines[index]
            if (line.isNotBlank() && line.indentWidth() <= declarationIndent) break
            body += line
        }
        return body
    }

    /** The isolated body of a fixture, for the assertions that inspect the isolation itself. */
    private fun isolatedBodyOf(fixture: String): List<String> {
        val lines = fixture.lines()
        val declarationIndex = lines.indexOfFirst { FUNCTION_DECLARATION.containsMatchIn(it) }
        assertTrue(declarationIndex >= 0, "the fixture carries no function declaration line to isolate from")
        return functionBodyAt(lines, declarationIndex)
    }

    // ── shared primitives, borrowed from the two repository-state precedents ──────────────

    private fun String.indentWidth(): Int = length - trimStart().length

    /**
     * [line] with a TRAILING `//` comment removed, so a triple quote written inside one cannot toggle
     * [dropRawStringInteriors]' raw-string state. The whole-line form is [isCommentOnly]'s job; this
     * is the other half of the same rule, added by the 27-REVIEW-3 WR-02 correction because the
     * in-code rule said "a comment" while the implementation only ever saw whole-line comments.
     *
     * IT IS A SMALL LEXER AND NOT A `substringBefore("//")`, AND THAT IS MEASURED RATHER THAN
     * CAUTIOUS. A `//` inside a string literal is not a comment, and cutting there discards whatever
     * follows — including a CLOSING triple quote. The counter-example is live on this tree today:
     *
     *     toolCall("scope_check", TQ{"url":"http://evil.example/"}TQ)   (TQ = a literal triple quote)
     *
     * `ui/ChatPanelToolGateTest.kt:113`. Cutting at the `//` of `http://` keeps the OPENING triple
     * quote and drops the CLOSING one, which leaves that file with an ODD count — so the naive strip
     * does not merely fail to fix WR-02, it takes a balanced repository file UNBALANCED and turns a
     * latent failure into a red one. MEASURED: it throws
     * `unbalanced triple quotes in com/six2dez/burp/aiagent/ui/ChatPanelToolGateTest.kt`. A
     * quote-PARITY guard does not save it either — `TQ{"url":"` is six quotes, an even count that
     * looks like "outside a string" while the raw string is open.
     *
     * So the scan tracks the three states a `//` can sit in and cuts only in the first: OUTSIDE any
     * string, inside a REGULAR string (where a backslash makes the next character opaque), and inside
     * a RAW string (where it does not, because Kotlin raw strings have no escapes). Nothing else is
     * interpreted — this is a triple-quote balance helper, not a Kotlin parser.
     */
    private fun trailingCommentStripped(line: String): String {
        var index = 0
        var inRawString = false
        var inRegularString = false
        while (index < line.length - 1) {
            val rawDelimiter = line.regionMatches(index, TRIPLE_QUOTE, 0, TRIPLE_QUOTE.length)
            var step = 1
            when {
                inRawString ->
                    if (rawDelimiter) {
                        inRawString = false
                        step = TRIPLE_QUOTE.length
                    }
                inRegularString ->
                    if (line[index] == '\\') {
                        step = 2
                    } else if (line[index] == '"') {
                        inRegularString = false
                    }
                rawDelimiter -> {
                    inRawString = true
                    step = TRIPLE_QUOTE.length
                }
                line[index] == '"' -> inRegularString = true
                line[index] == '/' && line[index + 1] == '/' -> return line.take(index)
            }
            index += step
        }
        return line
    }

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private data class Hit(
        val identifier: String,
        val argument: String,
        val vocabularyEntry: Int,
    ) {
        override fun toString(): String = "$identifier -> $argument (vocabulary entry $vocabularyEntry)"
    }

    private companion object {
        const val SELF_PATH = "com/six2dez/burp/aiagent/redact/RedactingPolicySurvivalSweepTest.kt"
        const val SELF_CLASS = "RedactingPolicySurvivalSweepTest"

        /** A numbered entry in the class KDoc's blind-axis enumeration; continuation lines do not match. */
        val AXIS_ENTRY = Regex("^\\s*\\*\\s+\\d+\\.\\s")

        /**
         * A `@Test` annotation at the START of a line, counted by
         * [theStatedTestMethodCountMatchesThisFilesOwnDeclarations].
         *
         * ANCHORED rather than a substring test, for the same reason [AXIS_ENTRY] is: a `@Test`
         * named in prose, in a KDoc reference or inside a string literal is not a declaration, and a
         * count that admitted those would drift for reasons that have nothing to do with the size of
         * this class. The word boundary keeps a hypothetical `@TestFactory` out of the count.
         */
        val TEST_ANNOTATION = Regex("^\\s*@Test\\b")

        // Measured at execution time: 151 .kt files under src/test/kotlin, this file included. The
        // floor is deliberately well below that — it is here to catch a walk that reaches nothing,
        // not to track the file count.
        const val MIN_EXPECTED_TEST_FILES = 100

        // Without the raw-string skip this file flags itself once per survival pin its positive
        // fixtures carry. The COUNT lives in STATED_UNSKIPPED_SELF_HITS and is machine-checked from
        // source; this floor is NOT that check and is deliberately kept well below it, for the same
        // reason the file floor is 100 — it is here to catch a skip that has silently disarmed the
        // detector, not to track a count. Plan 27-15 wrote the count into this comment (14) and plan
        // 27-12 wrote 5 before it; both went stale in place, the second of them inside the round that
        // wrote it, because a comment is not a check. The itemisation moved to the constant that a
        // test now reads.
        const val MIN_EXPECTED_UNSKIPPED_SELF_HITS = 2

        const val EXPECTED_NEGATIVE_FIXTURES = 6

        /**
         * The number of numbered axis entries in this class's own KDoc, MACHINE-CHECKED against that
         * enumeration by [theStatedBlindAxisCountMatchesTheEnumeration] rather than transcribed.
         *
         * This constant exists because the previous count did not have this property. Plan 27-12
         * wrote "Eleven axes" into the KDoc, `26-SECURITY.md` standing-rule clause (vi) cited that
         * eleven as the check's STATED BOUND, and the enumeration was already missing a live axis at
         * the moment both were written. Nothing went red, because nothing was checking. A number
         * transcribed by hand into two documents can only be kept honest by a third thing that reads
         * the source — so this is that thing, and the register now cites a number a test enforces.
         */
        const val STATED_BLIND_AXES = 13

        /**
         * The number of `@Test` methods this class declares, MACHINE-CHECKED against this file's own
         * declarations by [theStatedTestMethodCountMatchesThisFilesOwnDeclarations] rather than
         * transcribed.
         *
         * `26-SECURITY.md` standing-rule clause (vi) cites this class BY TEST COUNT, and that
         * citation went stale INSIDE the round that wrote the clause's other machine check: `fb7cbd3`
         * added a sixteenth `@Test` and a raw-string fixture, amended no record, and nothing was red.
         * Two counts in that clause were prose and both drifted; the one beside them that a test
         * read from source did not. This constant is the same remedy applied to the second of the
         * three.
         *
         * MEASURED 2026-08-26 at `2a880f9`: 16 declared, against a clause stating 15. The value here
         * is 18 — the sixteen at that commit plus
         * [theStatedTestMethodCountMatchesThisFilesOwnDeclarations] and
         * [theStatedUnskippedSelfHitCountMatchesThisFile], the two checks added to stop the drift.
         */
        const val STATED_TEST_METHODS = 18

        /**
         * The number of hits [detect] returns over THIS file with the raw-string skip NOT applied —
         * the falsifiability evidence `26-SECURITY.md` standing-rule clause (vi) quotes, pinned
         * EXACTLY by [theStatedUnskippedSelfHitCountMatchesThisFile].
         *
         * [MIN_EXPECTED_UNSKIPPED_SELF_HITS] floors the same population and is NOT replaced by this:
         * a floor catches a disarmed detector, an exact pin catches a moved count, and clause (vi)
         * quotes the count. Until this constant existed the clause's number was checked by nothing —
         * `fb7cbd3`'s TRAILING_COMMENT_WALK_FIXTURE added its one pin and moved the real figure from
         * 14 to 15 with every assertion in this class still green.
         *
         * MEASURED 2026-08-26 at `2a880f9`, against a clause stating 14. Itemised: the four
         * vocabulary fixtures carry FIVE pins between them (the host-pin fixture carries two);
         * [DECLARATION_SHAPE_FIXTURE] SIX, one per declaration shape; [WALK_COMPOSITION_FIXTURE] TWO,
         * one per half; [UNBALANCED_WALK_FIXTURE] ONE; [TRAILING_COMMENT_WALK_FIXTURE] ONE.
         * 5 + 6 + 2 + 1 + 1 = 15.
         */
        const val STATED_UNSKIPPED_SELF_HITS = 15

        // One hit per declaration shape in DECLARATION_SHAPE_FIXTURE. MEASURED against the SHIPPED
        // detector before this round's widening: 1 of 6 — only the plain-named control was seen.
        const val EXPECTED_DECLARATION_SHAPE_HITS = 6

        const val FIXTURE_ID = "<fixture>"
        const val TRIPLE_QUOTE = "\"\"\""
        const val CONTAINS_CALL = ".contains("
        const val ASSERT_TRUE = "assertTrue("
        const val ASSERT_FALSE = "assertFalse("
        const val ACCESSOR_SUFFIX = ".value"

        const val ENUM_ACCESSOR_ENTRY = 1
        const val HOST_LITERAL_ENTRY = 3

        val WHITESPACE_RUN = Regex("\\s+")

        /**
         * THE GATE EVERYTHING ELSE IN THIS FILE IS DOWNSTREAM OF, which is why it gets its own
         * paragraph rather than a trailing comment.
         *
         * [detect] returns early on a declaration line this does not match, so an unmatched
         * declaration makes its ENTIRE BODY invisible — not merely unnamed. A miss here is not a
         * naming defect and it is not an ordinary coverage gap: it is a hole in the scan itself.
         *
         * WHAT IT ADMITS, in order from the line start: leading whitespace; zero or more annotations,
         * each an at-sign, a word and an optional parenthesised argument list; zero or more bare
         * modifier tokens (`suspend`, `public`, `open`, `override`, `protected`, `inline`, `private`,
         * `internal`, in any order and any number); `fun`; an optional generic parameter list; and
         * then EITHER a plain identifier as CAPTURE GROUP 1 or a backtick-quoted one as CAPTURE
         * GROUP 2. The two groups are the reason [detect] reads group 1 and falls back to group 2:
         * reading a single fixed index silently yields an empty identifier for one of the two
         * spellings, and an empty identifier fails nothing.
         *
         * WHAT IT STILL DOES NOT ADMIT, stated here because naming the axis a widening creates is
         * the price of the widening: a declaration whose opening parenthesis does not follow the
         * identifier on the declaration line. Two shapes, both MEASURED on this tree after the
         * widening — an EXTENSION RECEIVER (`private fun String.indentWidth()`, 3 declarations, one
         * of them in this very file), and a MULTI-LINE SIGNATURE whose parenthesis sits on the next
         * line (0 today). Enumerated as blind axis 9 in the class KDoc.
         *
         * MEASURED before this widening, against the same tree: 133 of 1781 declaration lines
         * invisible — 136 of 1784 on the wider population 27-REVIEW-2 CR-01 counted, which includes
         * the 3 extension receivers above — 67 of them backtick-named `@Test` methods across 9 files,
         * 61 of them `override fun`. [everyDeclarationShapeInUseInThisRepositoryIsVisibleToTheSweep]
         * is the floor that keeps it from narrowing back.
         */
        val FUNCTION_DECLARATION =
            Regex("^\\s*(?:@\\w+(?:\\([^)]*\\))?\\s+)*(?:\\w+\\s+)*fun\\s+(?:<[^>]*>\\s*)?(?:(\\w+)|`([^`]+)`)\\s*\\(")

        /**
         * The tokens whose presence in a function body puts that body IN SCOPE. A body that names
         * none of these is not asserting anything about a redacting policy, and an `assertTrue` on a
         * sentinel under `PrivacyMode.OFF` is CORRECT rather than a defect.
         */
        val REDACTING_POLICY_MARKERS =
            listOf(
                "PrivacyMode.STRICT",
                "PrivacyMode.BALANCED",
                "RedactionPolicy.fromMode(",
            )

        /**
         * Sensitive fixture values that do NOT follow the sentinel naming convention but are
         * unmistakably sensitive. The fixture hostname the two pins removed in plan 27-12 asserted
         * as surviving is the only measured member.
         */
        val HOST_LITERALS = listOf("api.example.com")

        /**
         * The FOUR MEASURED forms a sensitive fixture value takes in this repository. Measured
         * against the tree, not guessed: a string literal in the `sentinel…` convention; the
         * `Sentinel.NAME.value` enum accessor used by `SerializedEmissionRedactionTest`; a bare
         * local identifier named `sentinel`; and a literal from [HOST_LITERALS].
         *
         * Every entry is paired one-for-one with an entry of [VOCABULARY_FIXTURES], so an entry that
         * has stopped matching cannot hide in the list and make the scan vacuously clean.
         */
        val SENSITIVE_VALUE_VOCABULARY =
            listOf(
                Regex("^\"sentinel[A-Za-z0-9]*\"$"),
                Regex("^Sentinel\\.[A-Z0-9_]+\\.value$"),
                Regex("^sentinel$"),
                Regex("^\"[^\"]*(" + HOST_LITERALS.joinToString("|") { Regex.escape(it) } + ")[^\"]*\"$"),
            )

        /**
         * The ONE accessor SUBTRACTED from the enum-accessor form, by construction rather than by an
         * [ALLOWLIST] key. `Sentinel.BENIGN_CONTROL` is the negative-control constant whose value is
         * the benign id in `SerializedEmissionRedactionTest`; asserting that it SURVIVES is the whole
         * point of a negative control — it proves a pass was not produced by blanket destruction of
         * the payload.
         *
         * MEASURED pre-existing count it accounts for on the tree as shipped: 7 live functions, all
         * in `SerializedEmissionRedactionTest`. Plan 27-12 projected 5; the two extra are the
         * JSON-string-open probes plan 27-11 added, each of which carries its own benign-control
         * assertion. The measured number is what is written here.
         *
         * Adding a SECOND key here is a decision requiring the same source-verified reason an
         * [ALLOWLIST] key would, and it costs blind axis 11 in the class KDoc. An eighth
         * benign-control assertion appearing later is normal; a second key is not.
         */
        val BENIGN_ACCESSORS = setOf("Sentinel.BENIGN_CONTROL")

        /**
         * Keyed by `file#function`, valued with a reason read from source.
         *
         * EMPTY, and expected to STAY empty: all three legitimate shapes measured on this tree are
         * excluded BY CONSTRUCTION in the detector — [BENIGN_ACCESSORS] (7 hits), the position rule
         * (1) and the negation rule (1) — rather than by a key here. An allowlist that quietly grows
         * entries is the tripwire failure mode `CookieCarrierInventoryTest` was warned about, and
         * [noGreenTestAssertsASensitiveValueSurvivesARedactingPolicy] reports STALE keys as loudly as
         * NEW hits so a dead key cannot accumulate either.
         */
        val ALLOWLIST = emptyMap<String, String>()

        // ── fixtures ──────────────────────────────────────────────────────────────────────
        //
        // EVERY fixture below is a VERBATIM copy of a real test function, held at COMPANION level
        // inside a triple-quoted raw string. Verbatim is the requirement: a shape invented here
        // would prove only that the detector finds shapes invented here. The single transformation
        // is that a literal `$` is written `${'$'}` — Kotlin interpolates raw strings — which is
        // value-preserving, so the fixture VALUE is byte-identical to its source. Where a fixture
        // contains a triple quote of its own, the same value-preserving escape is used.
        //
        // Nothing is inlined inside a `@Test` body, and no `@Test` body contains a literal sentinel,
        // a literal hostname or a literal policy token. That is what keeps every fixture INSIDE a raw
        // string where the file walk's skip can reach it.

        /**
         * POSITIVE, vocabulary entry 0 — a sensitive value written as a STRING LITERAL in the
         * `sentinel...` convention.
         *
         * The opening block of the pre-round `McpToolHelpersTest.cookieVariantsAreStrippedEndToEnd
         * ThroughRedactIfNeeded`, a contiguous slice, with ONE verb flipped from `assertFalse` to
         * `assertTrue` so the block now asserts the X-Cookie sentinel SURVIVES a redacting policy.
         * The tree carries no such pin in this form today, which is exactly why a fixture is needed:
         * an entry proven against nothing is an entry that can stop matching unnoticed.
         */
        val STRING_LITERAL_SENTINEL_FIXTURE =
            """
        fun cookieVariantsAreStrippedEndToEndThroughRedactIfNeeded() {
            val context = contextWith(PrivacyMode.STRICT, "end-to-end-salt")
            val rawHeaders =
                listOf(
                    stubHeader("X-Cookie", "sentinelxrayninezulu"),
                    stubHeader("Authorization", "Bearer sentineltokenoscarwhisky"),
                    stubHeader("Host", "api.example.com"),
                    stubHeader("X-Request-Id", "benignidcontrolvalue"),
                )

            val sanitizedJson = toolJson.encodeToString(parsedRequestOf(sanitizeHeaders(rawHeaders, context)))
            val finalText = context.redactIfNeeded(sanitizedJson)

            assertTrue(
                finalText.contains("sentinelxrayninezulu"),
                "the X-Cookie value must not survive the tool-result flow (got: ${'$'}finalText)",
            )
        }
            """

        /**
         * POSITIVE, vocabulary entry 1 — the `Sentinel.NAME.value` enum-accessor form, AND the floor
         * under the BENIGN_ACCESSORS exclusion.
         *
         * The real `SerializedEmissionRedactionTest.canonicalCookieDoesNotSurviveTheSerializedProxy
         * HistoryShapeUnderStrict` with ONLY its verb flipped, so it asserts a real, non-benign cookie
         * sentinel SURVIVES. It must be FLAGGED. Paired with NEGATIVE_ASSERT_FALSE_FIXTURE, which is
         * the same block UNFLIPPED and must be clean: the pair proves BENIGN_ACCESSORS subtracts ONE
         * NAMED CONSTANT and not the enum-accessor form itself. An exclusion that cannot be shown to
         * have a floor is just a quieter allowlist.
         */
        val ANTI_SWALLOW_FIXTURE =
            """
        fun canonicalCookieDoesNotSurviveTheSerializedProxyHistoryShapeUnderStrict() {
            val serialized = toolJson.encodeToString(proxyHistoryFixture())

            val redacted = contextWith(PrivacyMode.STRICT, "serialized-strict-salt").redactIfNeeded(serialized)

            assertTrue(
                redacted.contains(Sentinel.COOKIE_STRICT.value),
                "a canonical Cookie value must not survive STRICT redaction of the serialized " +
                    "proxy_http_history shape (got: ${'$'}redacted)",
            )
        }
            """

        /**
         * POSITIVE, vocabulary entry 2 — a bare local identifier named `sentinel`. ALSO the
         * machine-check on the function-body isolation, and the reason it is mandatory.
         *
         * The pre-round `CookieHeaderNameParityTest.thePredicateIsDeliberatelyWiderThanTheTwoRegexes`,
         * VERBATIM, blank lines preserved byte-for-byte. Its `fun` line is followed by two lines of
         * setup, then a BLANK LINE, then the predicate assertion, then a SECOND BLANK LINE, then the
         * mode loop carrying the redacting-policy marker, and only then the `assertTrue` on sentinel
         * survival. A blank-line-terminating isolation returns a nine-line stub containing neither the
         * marker nor the pin — a hit set of ZERO with every test still green. That is this round's
         * defect one iteration smaller, so it is asserted rather than assumed.
         *
         * Plan 27-10 has since renamed and inverted this test, which is why the copy comes out of
         * history rather than off the working tree.
         */
        val BLANK_LINE_HAZARD_FIXTURE =
            """
    fun thePredicateIsDeliberatelyWiderThanTheTwoRegexes() {
        val name = "my_cookie"
        val sentinel = PARITY_CORPUS.first { it.first == name }.second

        assertTrue(
            Redaction.isCookieHeaderName(name),
            "the shared predicate is a bare contains() and must match '${'$'}name'",
        )

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val output = redactHeaderBlob(mode, name, sentinel)
            assertTrue(
                output.contains(sentinel),
                "${'$'}mode: the prompt path must NOT strip '${'$'}name' — '_' is outside COOKIE_NAME_PART, so neither " +
                    "cookie regex can match it. This asymmetry is INTENTIONAL and fail-safe: the predicate is " +
                    "wider than the two regexes, so the redacting side over-matches rather than under-matches. " +
                    "If this assertion fails, the prompt-path regexes were widened — record the measurement, " +
                    "do not narrow the predicate to restore symmetry (output: ${'$'}output)",
            )
            assertFalse(
                output.contains("${'$'}name: [STRIPPED]"),
                "${'$'}mode: '${'$'}name' must not be rewritten to the stripped form (output: ${'$'}output)",
            )
        }
    }
            """

        /**
         * POSITIVE, vocabulary entry 3 — the host literal. Carries BOTH survival pins plan 27-12
         * removed, because in the real tree BOTH lived in ONE function and splitting them into two
         * invented functions would be less faithful, not more.
         *
         * The pre-round `McpToolHelpersTest.cookieVariantsAreStrippedEndToEndThroughRedactIfNeeded`,
         * VERBATIM. The detector must report EXACTLY 2 hits on it — one on the serialized raw-message
         * shape, one on the header-map shape — and the marker-to-pin distance spans many blank lines,
         * so this fixture carries the same two-token containment assertion as the hazard fixture.
         */
        val HOST_PIN_FIXTURE =
            """
        fun cookieVariantsAreStrippedEndToEndThroughRedactIfNeeded() {
            val context = contextWith(PrivacyMode.STRICT, "end-to-end-salt")
            val rawHeaders =
                listOf(
                    stubHeader("X-Cookie", "sentinelxrayninezulu"),
                    stubHeader("Authorization", "Bearer sentineltokenoscarwhisky"),
                    stubHeader("Host", "api.example.com"),
                    stubHeader("X-Request-Id", "benignidcontrolvalue"),
                )

            val sanitizedJson = toolJson.encodeToString(parsedRequestOf(sanitizeHeaders(rawHeaders, context)))
            val finalText = context.redactIfNeeded(sanitizedJson)

            assertFalse(
                finalText.contains("sentinelxrayninezulu"),
                "the X-Cookie value must not survive the tool-result flow (got: ${'$'}finalText)",
            )
            assertTrue(
                finalText.contains("X-Cookie"),
                "the header NAME must survive — only the VALUE is replaced (T-21-WA2) (got: ${'$'}finalText)",
            )
            assertTrue(
                finalText.contains("benignidcontrolvalue"),
                "negative control: this must be stripping, not blanket header loss (got: ${'$'}finalText)",
            )

            // (PRIV-05) 27-04 — WHAT THIS BLOCK PINS NOW, and what it deliberately no longer claims.
            //
            // AR-27-01 said redactIfNeeded could never recover a header sanitizeHeaders missed, which
            // made sanitizeHeaders the LAST line of defence rather than the first of two. Plan 27-04
            // taught the two cookie rules to recognise a JSON-ESCAPED newline as a logical line
            // boundary, so that is now SHAPE-DEPENDENT, and the two shapes are measured separately
            // below rather than generalised into one sentence.
            //
            // Shape 1, the RAW MESSAGE embedded in JSON — what proxy_http_history, site_map and
            // scanner_issues emit via Serialization.kt. Its CRLFs encode to the two literal
            // characters backslash-r / backslash-n, which the new branch keys on, so redactIfNeeded IS
            // now a genuine second control for the COOKIE-HEADER class on this shape: sanitizeHeaders
            // is defence in depth here rather than the only control. The recovery holds for the
            // cookie-header class ONLY.
            //
            // What is still NOT recoverable on this shape, stated so a reader cannot mistake the line
            // above for a general claim: the HOST header, because hostHeaderRegex still recognises
            // only the real-line boundary — recorded as open finding AR-27-04 in plan 27-06 — and any
            // VENDOR auth header outside authHeaderRegex's 16-name alternation, which no rule names at
            // all. (Names INSIDE that alternation are not listed here: plan 27-05 closes exactly those
            // one wave later using the same composer, so calling them unrecoverable would be a
            // sentence that goes false in wave 5 with nothing instructed to correct it.)
            val rawMessage =
                "GET / HTTP/1.1\r\n" +
                    rawHeaders.joinToString("") { "${'$'}{it.name()}: ${'$'}{it.value()}\r\n" } +
                    "\r\n"
            val rawMessageJson = toolJson.encodeToString(HttpRequestResponse(request = rawMessage, response = null, notes = null))
            val rawMessageFinalText = context.redactIfNeeded(rawMessageJson)

            assertFalse(
                rawMessageFinalText.contains("sentinelxrayninezulu"),
                "redactIfNeeded must now recover a cookie header sanitizeHeaders missed, on the " +
                    "serialized raw-message shape (got: ${'$'}rawMessageFinalText)",
            )
            // Non-vacuity guard, PRESERVED from the original pin: the very same call must really have
            // transformed its input, so an absence assertion cannot be passing because redactIfNeeded
            // silently no-opped on a wrong policy or a wrong context. bearerRegex is NOT line-anchored,
            // so it is the transformation that fires regardless of which line boundary the payload has.
            assertFalse(
                rawMessageFinalText.contains("sentineltokenoscarwhisky"),
                "redactIfNeeded must really have run under a redacting policy (got: ${'$'}rawMessageFinalText)",
            )
            // Measured, and the reason the guard above does NOT use the host: hostHeaderRegex is still
            // line-anchored, so STRICT host anonymisation cannot fire on this shape. AR-27-04.
            assertTrue(
                rawMessageFinalText.contains("api.example.com"),
                "measured AR-27-04: the line-anchored host rule cannot fire on the serialized " +
                    "raw-message shape (got: ${'$'}rawMessageFinalText)",
            )

            // Shape 2, the HEADER-MAP shape — what parsedRequestOf/ParsedRequest emits for
            // request_parse and response_parse, and the shape sanitizeHeaders actually guards.
            //
            // MEASURED CORRECTION to plan 27-04's own premise, which expected this assertion to invert
            // too: it does not, and inverting it would have committed a FALSE test. This payload
            // carries NO line boundary of ANY kind — the headers are JSON object members, not lines,
            // so there is neither a real newline for the shipped `^` anchor nor an ESCAPED one for the
            // new branch. The root cause is gated directly below instead of via its cookie
            // consequence, so this block contains no green assertion that a cookie value survives a
            // redacting policy — such an assertion is exactly what a later audit misreads as intent.
            //
            // The consequence, stated because it is real and bounded: for the COOKIE-HEADER class on
            // THIS shape, sanitizeHeaders remains the only control. The first half of this same test
            // is what gates that control end to end.
            val rawJson = toolJson.encodeToString(parsedRequestOf(rawHeaders.associate { it.name() to it.value() }))

            assertFalse(
                rawJson.contains("\\r") || rawJson.contains("\\n"),
                "the header-map shape must carry no line boundary at all — that, and not anything " +
                    "cookie-specific, is why neither branch of the cookie rules can fire here (got: ${'$'}rawJson)",
            )

            val rawFinalText = context.redactIfNeeded(rawJson)

            // Non-vacuity on this shape too: redactIfNeeded really ran under a redacting policy here
            // as well, so the boundary assertion above is not standing in for a call that no-opped.
            assertFalse(
                rawFinalText.contains("sentineltokenoscarwhisky"),
                "redactIfNeeded must really have run under a redacting policy (got: ${'$'}rawFinalText)",
            )
            assertTrue(
                rawFinalText.contains("api.example.com"),
                "measured AR-27-04: the line-anchored host rule cannot fire on the header-map shape " +
                    "either (got: ${'$'}rawFinalText)",
            )
        }
            """

        /**
         * NEGATIVE SHAPES 1 AND 2 — an `assertTrue` on a header NAME surviving, and an `assertTrue` on
         * the benign control value surviving, both under a redacting policy, in one real function.
         *
         * The real `SerializedEmissionRedactionTest.headerNameAndBenignControlSurviveTheSerialized
         * Shape`, VERBATIM. The header name SHOULD survive — only the VALUE is replaced (T-21-WA2) —
         * and the benign control SHOULD survive, or a pass could be produced by blanket destruction of
         * the payload. Neither is a survival pin.
         */
        val NEGATIVE_HEADER_NAME_FIXTURE =
            """
        fun headerNameAndBenignControlSurviveTheSerializedShape() {
            val serialized = toolJson.encodeToString(proxyHistoryFixture())

            val redacted = contextWith(PrivacyMode.STRICT, "serialized-control-salt").redactIfNeeded(serialized)

            assertTrue(
                redacted.contains("Cookie"),
                "the header NAME must survive — only the VALUE is replaced (T-21-WA2) (got: ${'$'}redacted)",
            )
            assertTrue(
                redacted.contains(Sentinel.BENIGN_CONTROL.value),
                "negative control: a value in a non-cookie header must survive, so a pass cannot be " +
                    "produced by blanket destruction of the payload (got: ${'$'}redacted)",
            )
        }
            """

        /**
         * NEGATIVE SHAPE 2, INDEPENDENTLY — a second benign-control survival, in a body naming BOTH
         * redacting policies through a mode loop.
         *
         * The real `SerializedEmissionRedactionTest.issueDetailsCarrierStripsCookiesInBothRedacting
         * Modes`, VERBATIM. This is one of the seven live functions the BENIGN_ACCESSORS exclusion
         * accounts for.
         */
        val NEGATIVE_BENIGN_CONTROL_FIXTURE =
            """
        fun issueDetailsCarrierStripsCookiesInBothRedactingModes() {
            val serialized = toolJson.encodeToString(issueDetailsFixture())

            listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED).forEach { mode ->
                val redacted = contextWith(mode, "issue-salt-${'$'}mode").redactIfNeeded(serialized)

                assertFalse(
                    redacted.contains(Sentinel.ISSUE_DETAILS_CARRIER.value),
                    "${'$'}mode: the scanner_issues carrier must strip the cookie value (got: ${'$'}redacted)",
                )
                assertTrue(
                    redacted.contains(Sentinel.BENIGN_CONTROL.value),
                    "${'$'}mode: negative control on the scanner_issues carrier (got: ${'$'}redacted)",
                )
                assertSameJsonShape(serialized, redacted)
            }
        }
            """

        /**
         * NEGATIVE SHAPE 3 — an `assertTrue` on a sentinel inside a body naming only `PrivacyMode.OFF`.
         *
         * Derived from the real `SerializedEmissionRedactionTest.offModeLeavesTheSerializedShapeByte
         * Identical` by substituting a containment assertion for its byte-identity one. Stated as a
         * derivation rather than passed off as verbatim: the tree carries no OFF-mode containment
         * assertion today, and the shape must still be tolerated, because under OFF pass-through IS the
         * correct behaviour. The body names no redacting policy, so it never enters scope at all.
         */
        val NEGATIVE_OFF_MODE_FIXTURE =
            """
        fun offModeLeavesTheSerializedShapeByteIdentical() {
            // The negative control that proves this is a POLICY-GATED strip and not unconditional
            // mangling. Byte equality against the un-redacted input, deliberately not a `contains`
            // check: a `contains` assertion would still pass if OFF mutated some other part of the
            // payload.
            val serialized =
                toolJson.encodeToString(
                    requestOnly("Cookie: wibble=${'$'}{Sentinel.OFF_MODE_CONTROL.value}"),
                )

            val redacted = contextWith(PrivacyMode.OFF, "off-mode-salt").redactIfNeeded(serialized)

            assertTrue(
                redacted.contains(Sentinel.OFF_MODE_CONTROL.value),
                "PrivacyMode.OFF must leave the cookie value in place",
            )
        }
            """

        /**
         * NEGATIVE SHAPE 4 — an `assertFalse` on a sentinel inside a body naming a redacting policy.
         *
         * The real `canonicalCookieDoesNotSurviveTheSerializedProxyHistoryShapeUnderStrict`, VERBATIM
         * and UNFLIPPED. The counterpart of ANTI_SWALLOW_FIXTURE.
         */
        val NEGATIVE_ASSERT_FALSE_FIXTURE =
            """
        fun canonicalCookieDoesNotSurviveTheSerializedProxyHistoryShapeUnderStrict() {
            val serialized = toolJson.encodeToString(proxyHistoryFixture())

            val redacted = contextWith(PrivacyMode.STRICT, "serialized-strict-salt").redactIfNeeded(serialized)

            assertFalse(
                redacted.contains(Sentinel.COOKIE_STRICT.value),
                "a canonical Cookie value must not survive STRICT redaction of the serialized " +
                    "proxy_http_history shape (got: ${'$'}redacted)",
            )
        }
            """

        /**
         * NEGATIVE SHAPE 5 — a PRE-REDACTION FIXTURE GUARD: an `assertTrue` on a sentinel positioned
         * ABOVE the line that first names the policy. MEASURED pre-existing count on this tree: 1.
         *
         * The real `SerializedEmissionRedactionTest.theRealTruncateIfNeededOutputShapeIsStrippedAndNot
         * Lengthened`, VERBATIM. Nothing has been redacted yet at that point in the body — the guard
         * asserts the value is present in the INPUT, which is what makes the later absence assertion
         * non-vacuous. The POSITION RULE excludes it, and blind axis 10 in the class KDoc is what that
         * exclusion costs.
         */
        val NEGATIVE_PRE_REDACTION_GUARD_FIXTURE =
            """
        fun theRealTruncateIfNeededOutputShapeIsStrippedAndNotLengthened() {
            val sentinel = Sentinel.TRUNCATION_HAZARD.value
            val serialized =
                toolJson.encodeToString(
                    requestOnly(
                        "Cookie: wibble=${'$'}sentinel\r\n" + "X-Filler: 0123456789012345678901234567890123456789\r\n".repeat(6),
                    ),
                )
            // Cut immediately AFTER a backslash that begins an encoded newline well past the cookie
            // header, so the sentinel is fully present in the truncated input (an absence assertion
            // must not be able to pass because truncation removed the sentinel itself) and the cut
            // lands mid-escape.
            val afterCookie = serialized.indexOf(sentinel) + sentinel.length
            val cutIndex = serialized.indexOf("\\r", serialized.indexOf("X-Filler", afterCookie)) + 1
            val truncated = truncateIfNeeded(serialized, cutIndex)

            assertTrue(truncated.contains(sentinel), "fixture guard: the sentinel must survive truncation itself")
            assertTrue(truncated.endsWith("bytes)"), "fixture guard: this must be the real truncateIfNeeded suffix shape")
            assertTrue(
                runCatching { toolJson.parseToJsonElement(truncated) }.isFailure,
                "fixture guard: the truncated input is already invalid JSON, which is why no parse gate applies here",
            )

            val redacted = contextWith(PrivacyMode.STRICT, "truncate-salt").redactIfNeeded(truncated)

            assertFalse(
                redacted.contains(sentinel),
                "the cookie value must still be stripped on the real truncated shape (got: ${'$'}redacted)",
            )
            assertTrue(
                redacted.length <= truncated.length,
                "the match must not run away: ${'$'}{redacted.length} > ${'$'}{truncated.length}",
            )
        }
            """

        /**
         * NEGATIVE SHAPE 6 — a NEGATED containment, `assertTrue(!x.contains(v))`: an ABSENCE assertion
         * wearing the wrong verb. MEASURED pre-existing count on this tree: 1.
         *
         * The real `RedactionTest.cookieHeaderNameVariantsAreStripped`, VERBATIM. The NEGATION RULE
         * excludes it. Its own triple-quoted input literal is escaped the same value-preserving way a
         * dollar is.
         */
        val NEGATIVE_NEGATED_CONTAINMENT_FIXTURE =
            """
    fun cookieHeaderNameVariantsAreStripped() {
        val input =
            ${'"'}${'"'}${'"'}
            GET / HTTP/1.1
            Host: example.com
            Cookie2: sentinelalphaone
            X-Cookie: sentinelbravotwo
            Set-Cookie2: sentinelcharliethree
            X-Original-Cookie: sentineldeltafour
            X-Forwarded-Cookie: sentinelechofive
            X-Request-Id: benignidcontrolvalue

            ${'"'}${'"'}${'"'}.trimIndent()

        val variants =
            listOf(
                "Cookie2" to "sentinelalphaone",
                "X-Cookie" to "sentinelbravotwo",
                "Set-Cookie2" to "sentinelcharliethree",
                "X-Original-Cookie" to "sentineldeltafour",
                "X-Forwarded-Cookie" to "sentinelechofive",
            )

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val policy = RedactionPolicy.fromMode(mode)
            val output = Redaction.apply(input, policy, stableHostSalt = "salt")

            for ((header, sentinel) in variants) {
                assertTrue(
                    !output.contains(sentinel),
                    "${'$'}mode: the value of ${'$'}header must not reach the prompt (leaked: ${'$'}output)",
                )
                assertTrue(
                    output.contains("${'$'}header: [STRIPPED]"),
                    "${'$'}mode: ${'$'}header must keep its OWN name, not be renamed to Cookie/Set-Cookie (got: ${'$'}output)",
                )
            }

            assertTrue(
                output.contains("X-Request-Id: benignidcontrolvalue"),
                "${'$'}mode: a header with no 'cookie' in its name must be left untouched (got: ${'$'}output)",
            )
        }
    }
            """

        /**
         * THE DECLARATION GATE, machine-checked over the six shapes this repository actually writes.
         *
         * One survival pin per declaration shape, each in the SAME assertion form the vocabulary
         * fixtures use, so the only variable between them is the DECLARATION LINE. Shape 6 is the
         * plain-named control: it was the ONE shape the pre-round detector could see, which is what
         * makes the other five a measurement rather than an assertion.
         *
         * These are shapes, not verbatim copies, and that departure from the file's verbatim rule is
         * deliberate and bounded: the repository carries no survival pin in ANY of these shapes today
         * — that is precisely the gap — so a verbatim copy is not available to take. What IS taken
         * from the tree is the POPULATION each shape stands in for, measured in
         * [everyDeclarationShapeInUseInThisRepositoryIsVisibleToTheSweep]'s failure message.
         */
        const val DECLARATION_SHAPE_FIXTURE =
            """
        fun `a backtick quoted name`() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentinelbacktickshape"),
                "shape 1 — a backtick-quoted name, the idiom 67 live @Test methods already use",
            )
        }

        @Test fun anAnnotationAndFunOnTheSameLine() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentinelannotationshape"),
                "shape 2 — an annotation and fun on one line",
            )
        }

        suspend fun aSuspendModifierPin() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentinelsuspendshape"),
                "shape 3 — a suspend modifier",
            )
        }

        public fun aPublicModifierPin() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentinelpublicshape"),
                "shape 4 — an explicit public modifier",
            )
        }

        override fun anOverrideModifierPin() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentineloverrideshape"),
                "shape 5 — an override modifier, 61 live declarations on this tree",
            )
        }

        fun aPlainDeclarationControl() {
            val redacted = contextWith(PrivacyMode.STRICT, "shape-salt").redactIfNeeded(payload)

            assertTrue(
                redacted.contains("sentinelplainshape"),
                "shape 6 — the CONTROL: the one shape the pre-round detector could see",
            )
        }
            """

        /**
         * THE WALK AND THE DETECTOR AS ONE COMPOSITION — the sweep's only production path, and until
         * plan 27-15 the only one with no positive gate.
         *
         * Two halves, and the assertion is that the walk treats them DIFFERENTLY. The first is a
         * companion-level raw string holding a survival-pin-shaped function, which the walk must
         * BLANK. The second is a real-code survival pin, which the walk must LEAVE ALONE so the
         * detector can flag it. Exactly one hit, and it must be the second one.
         *
         * Built by CONCATENATING [TRIPLE_QUOTE] rather than by embedding a literal triple quote:
         * this file scans ITSELF, and an embedded literal would toggle the walk's state mid-fixture.
         * That is the same reason [TRIPLE_QUOTE] is held at companion level at all.
         */
        const val WALK_COMPOSITION_FIXTURE =
            """
val aFixtureTheWalkMustBlank =
    """ + TRIPLE_QUOTE + """
    fun aPinThatLivesInsideTheRawString() {
        val redacted = contextWith(PrivacyMode.STRICT, "composition-salt").redactIfNeeded(payload)

        assertTrue(
            redacted.contains("sentinelinsidetherawstring"),
            "this pin is INSIDE a raw string and must be blanked by the walk",
        )
    }
    """ + TRIPLE_QUOTE + """

fun aRealCodePinTheWalkMustPreserve() {
    val redacted = contextWith(PrivacyMode.STRICT, "composition-salt").redactIfNeeded(payload)

    assertTrue(
        redacted.contains("sentinelrealcodepin"),
        "this pin is REAL CODE and must survive the walk to be flagged",
    )
}
            """

        /** The one hit [WALK_COMPOSITION_FIXTURE] must produce, and which of its two halves it is. */
        const val REAL_CODE_PIN_IDENTIFIER = "aRealCodePinTheWalkMustPreserve"

        /**
         * REAL CODE carrying a TRAILING `//` comment that mentions a triple quote, with a survival
         * pin below it.
         *
         * The walk must treat that comment as a comment: no toggle, no blanking, and no thrown
         * `AssertionError` — the file is BALANCED, and the only triple quote on it is inside a
         * comment. Before the 27-REVIEW-3 WR-02 correction this fixture ended INSIDE a raw string,
         * which since plan 27-15 is a THROW, so the two assertions below are a red-on-the-old-code
         * probe rather than a restatement.
         *
         * Built by CONCATENATING [TRIPLE_QUOTE] for the same reason [WALK_COMPOSITION_FIXTURE] is:
         * this file scans ITSELF, and an embedded literal would toggle the walk's state mid-fixture.
         * The splice line is also why the strip is skipped for a line that STARTS INSIDE a raw
         * string — on THIS file's own source that line's two triple quotes are real, and stripping at
         * its `//` would swallow them.
         */
        const val TRAILING_COMMENT_WALK_FIXTURE =
            """
val aLineWithATrailingComment = 1 // a raw string is opened with """ + TRIPLE_QUOTE + """ in Kotlin

fun aRealCodePinBelowATrailingComment() {
    val redacted = contextWith(PrivacyMode.STRICT, "trailing-comment-salt").redactIfNeeded(payload)

    assertTrue(
        redacted.contains("sentineltrailingcommentpin"),
        "this pin is REAL CODE below a trailing comment and must survive the walk to be flagged",
    )
}
            """

        /** The one hit [TRAILING_COMMENT_WALK_FIXTURE] must produce, and the line that must survive. */
        const val TRAILING_COMMENT_PIN_IDENTIFIER = "aRealCodePinBelowATrailingComment"
        const val TRAILING_COMMENT_CODE_LINE = "aLineWithATrailingComment"

        /**
         * A file that ENDS INSIDE a raw string — an ODD triple-quote count.
         *
         * The walk blanks every line below the unbalanced quote, so a survival pin anywhere in that
         * tail is invisible and the file's contribution to the tree scan is a vacuous zero. There is
         * no way to notice this from the hit set, which is why it must be a thrown error and not a
         * count.
         */
        const val UNBALANCED_WALK_FIXTURE =
            """
val anUnbalancedFixture =
    """ + TRIPLE_QUOTE + """
    fun aPinBelowTheUnbalancedQuote() {
        val redacted = contextWith(PrivacyMode.STRICT, "unbalanced-salt").redactIfNeeded(payload)

        assertTrue(redacted.contains("sentinelbelowtheunbalancedquote"), "invisible to the walk")
    }
            """

        /**
         * The identifier each shape of [DECLARATION_SHAPE_FIXTURE] must be reported under.
         *
         * Asserted as well as the count, because the widening moved which capture group carries a
         * plain name. A count that matches while every identifier is EMPTY would leave
         * [noGreenTestAssertsASensitiveValueSurvivesARedactingPolicy]'s allowlist-key comparison
         * comparing blanks, and it would do so without failing anything.
         */
        val DECLARATION_SHAPE_IDENTIFIERS =
            setOf(
                "a backtick quoted name",
                "anAnnotationAndFunOnTheSameLine",
                "aSuspendModifierPin",
                "aPublicModifierPin",
                "anOverrideModifierPin",
                "aPlainDeclarationControl",
            )

        /**
         * One positive fixture per [SENSITIVE_VALUE_VOCABULARY] entry, IN THE SAME ORDER, so an
         * entry that has stopped matching cannot hide in the list. The equal-size assertion in
         * [everyVocabularyEntryIsProvenLiveAgainstItsOwnPositiveFixture] keeps the pairing honest.
         */
        val VOCABULARY_FIXTURES =
            listOf(
                STRING_LITERAL_SENTINEL_FIXTURE,
                ANTI_SWALLOW_FIXTURE,
                BLANK_LINE_HAZARD_FIXTURE,
                HOST_PIN_FIXTURE,
            )

        /**
         * The SIX legitimate shapes that must NOT be flagged, every one of them taken from the real
         * tree rather than invented, because a shape invented here would prove only that the
         * detector tolerates shapes invented here.
         *
         * Two of them — the pre-redaction fixture guard and the negated containment — were
         * MEASURABLY FLAGGING under the unqualified vocabulary. They are the reason the constructed
         * exclusion count is three and not one.
         */
        val NEGATIVE_FIXTURES =
            listOf(
                "header NAME and benign control survive the serialized shape" to NEGATIVE_HEADER_NAME_FIXTURE,
                "benign control survives the issue-details carrier in both redacting modes" to NEGATIVE_BENIGN_CONTROL_FIXTURE,
                "a sentinel asserted present in a body naming only PrivacyMode.OFF" to NEGATIVE_OFF_MODE_FIXTURE,
                "an absence assertion on a sentinel under a redacting policy" to NEGATIVE_ASSERT_FALSE_FIXTURE,
                "a pre-redaction fixture guard, positioned above the policy marker" to NEGATIVE_PRE_REDACTION_GUARD_FIXTURE,
                "a negated containment — an absence assertion wearing the wrong verb" to NEGATIVE_NEGATED_CONTAINMENT_FIXTURE,
            )
    }
}
