package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * (PRIV-05) Phase 27 plan 27-10. THE BOUND FIRST, BEFORE ANY ASSERTION — read this before quoting
 * this file as evidence of anything.
 *
 * This file measures ONE AXIS: the CHARACTERS either side of the literal token in a header NAME.
 * It answers "for a name built from character X, do [Redaction.isCookieHeaderName] and the two
 * cookie regexes inside [Redaction.apply] agree?" and nothing else.
 *
 * IT IS BLIND TO EVERY OTHER AXIS THIS PHASE HAS BEEN REFUTED ON:
 *  - the emission SHAPE — a header rendered as a JSON-escaped line, inside a quoted value, or in a
 *    re-emitted cookie SECTION rather than at column 0;
 *  - the parameter TYPE — the same bytes reaching a prompt as an `HttpParameterType.COOKIE`
 *    parameter rather than as a header at all;
 *  - the issue-detail RENDERING — the same bytes reaching a backend through `AuditIssue.detail()`.
 * Each of those refuted a previous round of this phase, and each is owned elsewhere.
 *
 * SO THIS FILE IS NOT EVIDENCE OF COVERAGE. It is a width check over one axis, and a reader who
 * cites it as proof that the cookie-header control is complete reproduces, one iteration smaller,
 * exactly the defect this phase exists to repair: a record wider than the control it describes.
 *
 * WHAT IT DOES PIN, and this is the part with a shelf life longer than the phase:
 * [theCoveredSetIsReadFromRedactionSourceNotRetyped] READS the shipped `COOKIE_NAME_PART` character
 * class out of `Redaction.kt` and asserts it expands to exactly [COVERED_TCHARS]. Without that,
 * these three sets would be hand-typed copies asserted against each other — every test here would
 * stay green while [NOT_COVERED_TCHARS], the set `AR-27-10` is filed from, went quietly false.
 */
class CookieHeaderNameWidthTest {
    @BeforeEach
    fun clearCustomPatterns() {
        // Redaction is a singleton object: a custom pattern left behind by another test class in the
        // same JVM could remove a sentinel for the wrong reason, making a removal look like a cookie
        // rule firing when it was not. Same discipline as CookieHeaderNameParityTest.
        Redaction.setCustomPatterns(emptyList())
    }

    @AfterEach
    fun clearCustomPatternsAfterEach() {
        clearCustomPatterns()
    }

    // Behavioural agreement over the covered class: for each sampled character, the predicate claims
    // the name AND the prompt path removes its value. One header line per invocation, so a sentinel
    // can only be removed by a rule that claims THAT name.
    @Test
    fun theCoveredCharacterClassIsStrippedByBothTheRegexesAndThePredicate() {
        for ((character, sentinel) in COVERED_SAMPLE) {
            val name = "${character}cookie$character"

            assertTrue(
                Redaction.isCookieHeaderName(name),
                "the shared predicate must claim '$name' — it contains the token",
            )

            for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
                val output = redactHeaderLine(mode, name, sentinel)
                assertFalse(
                    output.contains(sentinel),
                    "$mode: the value of '$name' SURVIVED a redacting policy. '$character' is inside the " +
                        "class COOKIE_NAME_PART now admits, so the predicate and the two cookie regexes are " +
                        "supposed to AGREE on this name. They do not, which means a name " +
                        "PassiveAiScannerFilters.sanitizeHeadersForPrompt ADMITS onto the outbound prompt is a " +
                        "name Redaction.apply cannot strip — fail-OPEN. Widen COOKIE_NAME_PART; never narrow " +
                        "the predicate (output: $output)",
                )
                assertTrue(
                    output.contains("$name: [STRIPPED]"),
                    "$mode: '$name' must keep its OWN name when stripped rather than be renamed to the " +
                        "canonical spelling (output: $output)",
                )
            }
        }
    }

    // What makes NOT_COVERED_TCHARS load-bearing rather than prose compiled into a class file. A set
    // that is merely declared is a comment with a type; a set asserted to be the exact complement of
    // a measured set is evidence.
    @Test
    fun theThreeCharacterSetsPartitionEachOther() {
        assertTrue(
            COVERED_TCHARS.isNotEmpty(),
            "COVERED_TCHARS is empty — every behavioural assertion in this file would iterate nothing",
        )
        assertTrue(
            NOT_COVERED_TCHARS.isNotEmpty(),
            "NOT_COVERED_TCHARS is empty, which would claim the regexes cover the FULL tchar set. If a " +
                "later widening genuinely achieved that, delete AR-27-10 deliberately rather than letting " +
                "this assertion be the thing that noticed",
        )
        assertTrue(
            (COVERED_TCHARS intersect NOT_COVERED_TCHARS).isEmpty(),
            "COVERED_TCHARS and NOT_COVERED_TCHARS overlap on " +
                "${COVERED_TCHARS intersect NOT_COVERED_TCHARS} — they are supposed to be complements",
        )
        assertEquals(
            ALL_RFC9110_TCHARS,
            COVERED_TCHARS + NOT_COVERED_TCHARS,
            "the two subsets must reconstruct the whole tchar population exactly, or the axis this file " +
                "claims to enumerate has a hole nothing is looking at",
        )
    }

    // Cardinality and sample guards. A corpus that silently emptied, or a population quietly reduced
    // to the characters that happen to pass, must FAIL rather than pass about nothing.
    @Test
    fun theScanIsNonVacuous() {
        assertEquals(
            TCHAR_PUNCTUATION_COUNT,
            TCHAR_PUNCTUATION.toSet().size,
            "RFC 9110 gives tchar exactly $TCHAR_PUNCTUATION_COUNT punctuation characters; " +
                "TCHAR_PUNCTUATION holds ${TCHAR_PUNCTUATION.toSet().size} distinct ones",
        )
        assertEquals(
            TCHAR_PUNCTUATION_COUNT + DIGIT_COUNT + LETTER_COUNT,
            ALL_RFC9110_TCHARS.size,
            "the tchar population must be $TCHAR_PUNCTUATION_COUNT punctuation + $DIGIT_COUNT digits + " +
                "$LETTER_COUNT letters",
        )
        assertEquals(
            EXPECTED_NOT_COVERED_COUNT,
            NOT_COVERED_TCHARS.size,
            "the residual filed as AR-27-10 is $EXPECTED_NOT_COVERED_COUNT characters; it now measures " +
                "${NOT_COVERED_TCHARS.size} (${NOT_COVERED_TCHARS.sorted().joinToString("")}). If " +
                "COOKIE_NAME_PART moved, re-derive the register entry from this measurement",
        )
        assertTrue(
            COVERED_SAMPLE.isNotEmpty(),
            "the behavioural test above iterates COVERED_SAMPLE — an empty list makes it pass about nothing",
        )
        assertEquals(
            COVERED_SAMPLE.size,
            COVERED_SAMPLE.map { it.second }.toSet().size,
            "each sampled character needs its OWN sentinel, or an absence assertion can be satisfied by " +
                "another character's rule",
        )
        COVERED_SAMPLE.forEach { (character, _) ->
            assertTrue(
                character in COVERED_TCHARS,
                "the sample iterates '$character', which is not in COVERED_TCHARS — the behavioural test " +
                    "would be asserting agreement over a character the class does not claim",
            )
        }
    }

    // THE ANTI-DRIFT PIN, and the reason the three tests above are worth anything. Widen or narrow
    // the shipped COOKIE_NAME_PART later and this test goes RED, instead of leaving NOT_COVERED_TCHARS
    // — and AR-27-10's evidence — silently false while everything else stays green.
    @Test
    fun theCoveredSetIsReadFromRedactionSourceNotRetyped() {
        val declarations =
            SourceRoots
                .file(REDACTION_SOURCE)
                .readLines()
                .filter { COOKIE_NAME_PART_DECLARATION.containsMatchIn(it) }

        assertEquals(
            1,
            declarations.size,
            "expected exactly ONE COOKIE_NAME_PART declaration in $REDACTION_SOURCE, found " +
                "${declarations.size}: $declarations. This test reads the shipped class out of source; it " +
                "cannot do that if the declaration is duplicated or gone",
        )

        val shipped = declarations.single().substringAfter("\"[").substringBefore("]*\"")

        assertEquals(SHIPPED_CHAR_CLASS, shipped, driftMessage(shipped))
        assertEquals(COVERED_TCHARS, expandCharClass(shipped), driftMessage(shipped))

        // NON-VACUITY FOR THE EXPANDER, mandatory: an expander that ignored its argument and returned
        // COVERED_TCHARS would pass both assertions above while proving nothing.
        assertEquals(
            setOf('a', 'b', 'c', '1'),
            expandCharClass("a-c1"),
            "expandCharClass no longer expands a known class correctly, so its verdict on the shipped " +
                "class means nothing",
        )
        assertNotEquals(
            COVERED_TCHARS,
            expandCharClass(PRE_FIX_CHAR_CLASS),
            "expandCharClass cannot tell the PRE-FIX class [$PRE_FIX_CHAR_CLASS] apart from the shipped " +
                "one, so it is an identity function returning the answer it was asked to check. This " +
                "assertion FAILS on the unfixed tree, which is what makes it a probe rather than a " +
                "restatement",
        )
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────

    private fun driftMessage(shipped: String): String =
        "the shipped COOKIE_NAME_PART character class is now [$shipped], not [$SHIPPED_CHAR_CLASS]. " +
            "COVERED_TCHARS, NOT_COVERED_TCHARS and the AR-27-10 register entry are all derived from that " +
            "constant and are ALL STALE — re-derive them together rather than editing this test to match. " +
            "Note the direction rule while you do: COOKIE_NAME_PART must stay at least as wide as whatever " +
            "Redaction.isCookieHeaderName admits, because one of that predicate's consumers " +
            "(PassiveAiScannerFilters.sanitizeHeadersForPrompt) is an ADMITTER, where narrower is fail-open."

    /** Expands a regex character class body to its characters: `X-Y` is a range, anything else literal. */
    private fun expandCharClass(spec: String): Set<Char> {
        val expanded = mutableSetOf<Char>()
        var index = 0
        while (index < spec.length) {
            val isRange = index + RANGE_SPEC_LENGTH <= spec.length && spec[index + 1] == '-'
            if (isRange) {
                (spec[index]..spec[index + RANGE_SPEC_LENGTH - 1]).forEach { expanded.add(it) }
                index += RANGE_SPEC_LENGTH
            } else {
                expanded.add(spec[index])
                index += 1
            }
        }
        return expanded
    }

    private fun redactHeaderLine(
        mode: PrivacyMode,
        name: String,
        sentinel: String,
    ): String {
        val blob = "GET / HTTP/1.1\nHost: example.com\n$name: $sentinel\n"
        return Redaction.apply(blob, RedactionPolicy.fromMode(mode), stableHostSalt = WIDTH_HOST_SALT)
    }

    private companion object {
        const val REDACTION_SOURCE = "com/six2dez/burp/aiagent/redact/Redaction.kt"
        const val WIDTH_HOST_SALT = "phase-27-plan-10-width-salt"

        /** Length of a `X-Y` range in a character-class body. */
        const val RANGE_SPEC_LENGTH = 3

        /** The class plan 27-10 ships inside COOKIE_NAME_PART, character for character. */
        const val SHIPPED_CHAR_CLASS = "A-Za-z0-9_-"

        /** The class that shipped BEFORE plan 27-10 — quoted as HISTORY, and used as a red probe. */
        const val PRE_FIX_CHAR_CLASS = "A-Za-z0-9-"

        val COOKIE_NAME_PART_DECLARATION = Regex("^\\s*private const val COOKIE_NAME_PART\\s*=")

        /** The fifteen punctuation characters RFC 9110 admits in a field-name token. */
        const val TCHAR_PUNCTUATION = "!#\$%&'*+-.^_`|~"

        const val TCHAR_PUNCTUATION_COUNT = 15
        const val DIGIT_COUNT = 10
        const val LETTER_COUNT = 52
        const val EXPECTED_NOT_COVERED_COUNT = 13

        /** The axis's stated POPULATION: the full RFC 9110 tchar set. */
        val ALL_RFC9110_TCHARS: Set<Char> =
            TCHAR_PUNCTUATION.toSet() + ('0'..'9') + ('A'..'Z') + ('a'..'z')

        /**
         * What COOKIE_NAME_PART admits after plan 27-10. This is a MEASUREMENT, not a second copy of
         * the shipped constant: [theCoveredSetIsReadFromRedactionSourceNotRetyped] reads that constant
         * out of `Redaction.kt` and asserts it expands to exactly this set.
         */
        val COVERED_TCHARS: Set<Char> = setOf('_', '-') + ('0'..'9') + ('A'..'Z') + ('a'..'z')

        /**
         * The residual — THE NEXT BLIND AXIS, enumerated in source and filed as `AR-27-10`. DERIVED as
         * the complement, never hand-listed: a hand-listed complement is a third copy to keep in sync,
         * and it would go stale in silence the moment either of the other two sets moved.
         */
        val NOT_COVERED_TCHARS: Set<Char> = ALL_RFC9110_TCHARS - COVERED_TCHARS

        /**
         * One sentinel per sampled character, each a bare lowercase alphabetic word so that — per the
         * fixture-reachability note in CookieHeaderNameParityTest — no rule other than a cookie header
         * rule can remove it.
         */
        val COVERED_SAMPLE: List<Pair<Char, String>> =
            listOf(
                'a' to "sentinelwidthloweralpha",
                'Z' to "sentinelwidthupperalpha",
                '0' to "sentinelwidthdigitzero",
                '9' to "sentinelwidthdigitnine",
                '_' to "sentinelwidthunderscore",
                '-' to "sentinelwidthhyphen",
            )
    }
}
