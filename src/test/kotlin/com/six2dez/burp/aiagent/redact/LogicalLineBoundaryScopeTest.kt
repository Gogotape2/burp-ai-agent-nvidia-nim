package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * (PRIV-05) Phase 27 plans 27-04 + 27-05 / D-27-13 — which redaction rules carry the logical-line
 * boundary, pinned from source.
 *
 * WHAT THIS IS FOR.
 *
 * Plan 27-04 taught three header rules that a JSON-escaped newline is a logical line start, by
 * routing them through ONE composer, `Redaction.logicalLineHeaderRule`. Because it is one composer,
 * a single token carries the whole claim: a rule that STOPPED using it, or a fourth rule that
 * STARTED, is a one-line edit that would otherwise be invisible in review.
 *
 * `hostHeaderRegex` is deliberately NOT in that set (D-27-13), and the reason is measured rather
 * than aesthetic: it rewrites through `anonymizeHost`, which records into the de-anonymisation map
 * that `RedactionHostMapBoundTest` exists to bound, and `SiteMapEntry.url` carries the same host
 * verbatim with no `maybeAnonymizeUrl` in front of it — so anonymising the header alone would
 * produce a control that reads as closed and is not. That exclusion is a DECISION, and a decision
 * that lives only in a SUMMARY drifts from the code the first time someone "fixes" it in passing.
 *
 * So this file asserts the composition and the record TOGETHER: the three rules that carry the
 * composer, the one that must not, and the rationale comment that has to keep naming the excluded
 * rule. A reader who finds the code and the record disagreeing has found a real regression.
 *
 * WHAT THIS IS BOUNDED BY — read this before quoting it as evidence.
 *
 * It is a tripwire over FOUR NAMED RULES in ONE NAMED FILE, `redact/Redaction.kt`. A FIFTH rule with
 * the same blind spot, a rule in another file, or a header matcher that never reaches this file at
 * all is invisible to it and leaves it GREEN. It says nothing about whether the boundary is the
 * RIGHT one — the behavioural evidence for that is `SerializedEmissionRedactionTest` and
 * `RedactionTest`, not a source scan. `CookieHeaderRuleOwnershipTest` states its own bound in the
 * same place and for the same reason.
 */
class LogicalLineBoundaryScopeTest {
    @Test
    fun theBoundaryFragmentsAreComposedIntoTheMeasuredRuleSetAndNoOther() {
        // The POSITIVES are asserted first and individually, so this test cannot pass because the
        // isolation helper quietly returned nothing. A negative-only gate over an empty block is
        // exactly the decorative tripwire T-27-05-04 exists to prevent.
        COMPOSED_RULES.forEach { rule ->
            val block = declarationBlockOf(rule)
            assertEquals(
                1,
                block.count { it.contains(COMPOSER_CALL) },
                "$rule must be built by exactly one `$COMPOSER_CALL` call. Plan 27-04 routed every " +
                    "logical-line header rule through ONE composer so the boundary cannot be edited " +
                    "for one rule and forgotten for the others — a hand-inlined rule here is that " +
                    "drift beginning.\n  Declaration block read as: $block",
            )
        }

        // The negative below is only worth anything if the helper actually FOUND the declaration.
        // The guard checks that and nothing more: probing for a particular initializer shape (say a
        // literal `Regex(`) would couple this to how the excluded rule happens to be written today,
        // and would then fire INSTEAD of the assertion that carries the claim.
        val excludedBlock = declarationBlockOf(EXCLUDED_RULE)
        assertTrue(
            excludedBlock.firstOrNull()?.contains("private val $EXCLUDED_RULE") == true,
            "the isolation helper returned no declaration for $EXCLUDED_RULE, so the negative " +
                "assertion below would prove nothing. Read as: $excludedBlock",
        )
        assertEquals(
            0,
            excludedBlock.count { it.contains(COMPOSER_CALL) },
            "$EXCLUDED_RULE must NOT be routed through `$COMPOSER_CALL` (D-27-13). Two measured " +
                "reasons: anonymizeHost writes into a de-anonymisation map bounded by " +
                "RedactionHostMapBoundTest, and firing it on every raw message of every site_map / " +
                "proxy_http_history result is an unmeasured load change on that bound; and " +
                "SiteMapEntry.url carries the same host VERBATIM with no maybeAnonymizeUrl in front " +
                "of it, so anonymising the header alone yields a payload whose `request` is " +
                "anonymised and whose `url` is not — a control that reads as closed and is not. " +
                "If this is now deliberate, close the url field too and update AR-27-04, the " +
                "rationale comment and this constant together.\n  Declaration block read as: $excludedBlock",
        )
    }

    @Test
    fun theScopeScanIsNonVacuous() {
        // Resolving the file is the first assertion: sourceFile() throws AssertionError rather than
        // returning null, so a scan that cannot find the repository FAILS instead of going green.
        val lines = sourceFile().readLines()
        assertTrue(
            lines.size >= MIN_EXPECTED_LINES,
            "$RULE_OWNER has ${lines.size} lines, below the floor of $MIN_EXPECTED_LINES — the scan " +
                "is looking at the wrong file, or the file it pins has been gutted",
        )

        // Every symbol this file reasons about must actually be declared, or an assertion that
        // "the composer appears zero times here" could be true because nothing exists at all.
        (COMPOSED_RULES + EXCLUDED_RULE).forEach { rule ->
            assertTrue(
                declarationBlockOf(rule).isNotEmpty(),
                "no declaration of `$rule` found in $RULE_OWNER — every assertion about it is vacuous",
            )
        }
        REQUIRED_DECLARATIONS.forEach { declaration ->
            assertTrue(
                lines.any { it.trimStart().startsWith(declaration) },
                "`$declaration` is no longer declared in $RULE_OWNER. The composer and its three " +
                    "fragments are what the boundary rationale is written against; if they were " +
                    "renamed or inlined, this test's constants describe a file that no longer exists.",
            )
        }

        // And comment stripping is proven live. The rationale block in that file NAMES every symbol
        // these scans look for, so an unfiltered match would read prose as composition.
        assertTrue(isCommentOnly("    // $COMPOSER_CALL"), "the comment filter no longer recognises a line comment")
        assertTrue(isCommentOnly("     * $COMPOSER_CALL"), "the comment filter no longer recognises a KDoc body line")
        assertTrue(
            (COMPOSED_RULES + EXCLUDED_RULE).flatMap { declarationBlockOf(it) }.none { isCommentOnly(it) },
            "a comment-only line reached a declaration block",
        )
    }

    @Test
    fun theStatedBoundIsPresentWhereAReaderMeetsIt() {
        // The record and the source state have to move together. This asserts the rationale block a
        // reader actually meets — the contiguous comment region immediately above the boundary
        // fragments — still names what the composition below it does and does not cover.
        val rationale = rationaleRegionAboveFragments()
        assertTrue(
            rationale.size >= MIN_RATIONALE_LINES,
            "the rationale region above `${REQUIRED_DECLARATIONS.first()}` is only ${rationale.size} " +
                "lines. The bound is supposed to be stated where a reader meets it, not in a planning " +
                "document they will not open.",
        )
        val text = rationale.joinToString("\n")

        assertTrue(
            text.contains(EXCLUDED_RULE),
            "the rationale above the boundary fragments no longer names `$EXCLUDED_RULE` as the " +
                "deliberate exclusion. The code excludes it; if the comment stops saying so, the next " +
                "reader meets a composer with no statement of what it does not cover — which is how " +
                "a record ends up wider than the control it describes.",
        )
        assertTrue(
            text.contains(OPEN_FINDING),
            "the rationale must carry the open-finding id `$OPEN_FINDING`, so the residual stays " +
                "traceable from source to the phase record rather than surviving as an aside",
        )
        assertTrue(
            text.contains(SECOND_FINDING_CLOSED_BY_FIX),
            "the rationale must ALSO carry `$SECOND_FINDING_CLOSED_BY_FIX`, the leading-whitespace / " +
                "obs-fold start. It is CLOSED BY FIX as of 27-17 rather than open, and it stays named " +
                "here for that reason and not despite it: the register entry and the source state " +
                "have to move together, so a reader who finds the id in `26-SECURITY.md` can see in " +
                "source what closed it. A closure recorded only in a planning document is one " +
                "refactor away from a silent revert.",
        )
        assertTrue(
            text.contains(SECOND_FINDING_CLOSURE_MARKER),
            "the rationale names `$SECOND_FINDING_CLOSED_BY_FIX` but does not say " +
                "`$SECOND_FINDING_CLOSURE_MARKER`. The id was OPEN for two rounds and the wording " +
                "that went with it said the fourth start was NOT recognised. If the code has been " +
                "fixed and the comment still reads as a live residual, the next reader is told the " +
                "boundary is narrower than it is — which is the mirror image of the " +
                "record-wider-than-control defect this file exists to catch, and just as wrong.",
        )
        assertTrue(
            text.contains(REAL_LINE_START_DECLARATION.substringAfterLast(' ')),
            "the rationale must name `${REAL_LINE_START_DECLARATION.substringAfterLast(' ')}` — the " +
                "constant that closes `$SECOND_FINDING_CLOSED_BY_FIX`. Stating the closure without " +
                "naming what performs it leaves the claim unanchored to code.",
        )
        assertTrue(
            text.contains(THIRD_OPEN_FINDING),
            "the rationale must ALSO carry `$THIRD_OPEN_FINDING` — the JSON-STRING-OPEN start in " +
                "EVERY spelling `:\"` does not recognise, which is FOUR MEASURED families and not " +
                "the one array-element example this message used to name. The mechanism, so the " +
                "list is not read as four accidents: `:\"` is the two LITERAL characters colon then " +
                "quote, so any shape that interposes a character between them — a space, or the " +
                "backslash of an escaped quote — and any shape with no colon before the quote at " +
                "all, is NOT a start. ALL THREE residuals have to stay traceable from source: the " +
                "boundary now recognises a NARROWED set of logical line starts, and a comment that " +
                "stops naming what the boundary cannot see leaves the next reader with a boundary " +
                "that reads complete and is not — which is how this requirement has been closed " +
                "wrongly FOUR times already.",
        )
        COMPOSED_RULES.forEach { rule ->
            assertTrue(
                text.contains(rule),
                "the rationale above the boundary fragments does not name `$rule`, which IS composed " +
                    "from them. The stated set and the composed set must match exactly.",
            )
        }
    }

    /**
     * (PRIV-05) 27-14 — THE ANTI-DRIFT PIN on the third start's VALUE, not just its name.
     *
     * Plan 27-11 shipped `JSON_STRING_OPEN` as a BARE double quote while calling it a JSON string
     * open, and every existing guard in this file stayed green: [REQUIRED_DECLARATIONS] asserts the
     * declaration PREFIX, and the composition scans assert which rules carry the boundary. Neither
     * looks at what the constant is worth. A one-character revert would therefore ship green a
     * SECOND time, which is the exact failure mode this test exists to remove.
     *
     * The value is READ OUT OF `Redaction.kt` at test time rather than re-typed, on the
     * `CookieHeaderNameWidthTest.theCoveredSetIsReadFromRedactionSourceNotRetyped` precedent — a
     * retyped expectation drifts silently, a source-read one cannot.
     */
    @Test
    fun theJsonStringOpenIsAValueOpenAndNotABareQuote() {
        // Comment-only lines are filtered FIRST: the rationale block above the fragments names this
        // symbol in prose several times, and an unfiltered count would read that prose as a
        // declaration and make the "exactly one" assertion wrong for the wrong reason.
        val declarations =
            sourceFile()
                .readLines()
                .filterNot { isCommentOnly(it) }
                .filter { it.trimStart().startsWith(JSON_STRING_OPEN_DECLARATION) }

        assertEquals(
            1,
            declarations.size,
            "`$JSON_STRING_OPEN_DECLARATION` must be declared EXACTLY once in $RULE_OWNER, or the " +
                "value assertion below is reading one of several and proves nothing about the " +
                "boundary the composer actually uses.\n  Read as: $declarations",
        )

        val literal = declarations.single().substringAfter("=").trim()
        assertTrue(
            literal.length >= 2 && literal.startsWith("\"") && literal.endsWith("\""),
            "the initializer of `$JSON_STRING_OPEN_DECLARATION` is not a plain string literal, so it " +
                "cannot be decoded here. Read as: $literal",
        )

        val decoded = decodeKotlinStringLiteral(literal)

        assertEquals(
            EXPECTED_JSON_STRING_OPEN_WIDTH,
            decoded.length,
            "the third logical-line start must stay FIXED-WIDTH at $EXPECTED_JSON_STRING_OPEN_WIDTH " +
                "characters. A width-one value here means the bare double quote 27-11 shipped is " +
                "back: a bare quote is NOT a JSON string open — it also opens HTML attribute values, " +
                "JS string literals and quoted CSV fields — and it was MEASURED destroying 1589 of " +
                "1714 characters of a realistic serialized tool result, removing all forty of its " +
                "content markers while leaving the JSON structurally valid, so every shape assertion " +
                "passed and the model read a truncated body. Widening this constant back is a " +
                "CORRECTNESS REGRESSION on the primary MCP emission path, not a tightening.\n" +
                "  Read as: $literal",
        )
        assertEquals(
            ":\"",
            decoded,
            "the third logical-line start must be the colon-quote sequence — a JSON string VALUE " +
                "open. The narrowing deliberately accepts one residual, recorded as AR-27-11, and " +
                "that residual is a MECHANISM rather than an example: `:\"` is colon then quote " +
                "LITERALLY, so a header at the open of a JSON string escapes whenever a character " +
                "is interposed between the two — or there is no colon at all. FOUR families were " +
                "MEASURED matching before 27-14 and byte-unchanged after, in STRICT and BALANCED " +
                "and across all three composed rules: a NESTED / ESCAPED value open " +
                "(`\\\"k\\\":\\\"Cookie: …`, which is a captured JSON RESPONSE BODY serialized into " +
                "a tool result, so it sits on the PRIMARY emission path); PRETTY-PRINTED JSON " +
                "(`\"k\": \"Cookie: …`); a BARE TOP-LEVEL JSON string; and the ARRAY ELEMENT " +
                "(`[\"Cookie: …\"]` and `,\"Cookie: …`) this message once named alone. In all four " +
                "only a header that is the FIRST CONTENT of its string escapes — one after an " +
                "escaped newline is still stripped — which is the bound the MEDIUM rests on. " +
                "That trade is the whole of what the narrowing bought; do not undo it by re-widening " +
                "this value, and do not re-widen it to `[\\\"` and `,\\\"` alone believing that " +
                "closes AR-27-11: it closes ONE of the four. See the `AR-27-11` row in " +
                "`26-SECURITY.md` for the re-derivation.\n" +
                "  Read as: $literal",
        )
    }

    /**
     * (PRIV-05) 27-17 — THE ANTI-DRIFT PIN on the FOURTH start's VALUE, closing `AR-27-09`.
     *
     * The finding was MEASURED, twice, as `GET / HTTP/1.1\r\n Cookie: a=SECRET5\r\n\r\n` surviving
     * `Redaction.apply` BYTE-UNCHANGED under STRICT and under BALANCED — canonical `Cookie:`, with
     * the un-indented control stripping in the same run. What put it back inside the boundary is a
     * change of nine characters in one constant. Reverting it is the same nine characters, and every
     * other guard in this file — the composition scans, the declaration-existence scan, the rationale
     * scan — would stay green through that revert, exactly as they stayed green through the bare
     * double quote 27-11 shipped under the name `JSON_STRING_OPEN`.
     *
     * So the VALUE is read out of `Redaction.kt` at test time, never re-typed, on the
     * `CookieHeaderNameWidthTest.theCoveredSetIsReadFromRedactionSourceNotRetyped` precedent.
     *
     * This asserts the START, not the survival: the behavioural evidence lives in
     * `IndentedLogicalLineStartTest`, which drives `Redaction.apply` end to end in both redacting
     * modes over all three composed rules.
     */
    @Test
    fun theRealLineStartRecognisesLeadingHorizontalWhitespace() {
        val declarations =
            sourceFile()
                .readLines()
                .filterNot { isCommentOnly(it) }
                .filter { it.trimStart().startsWith(REAL_LINE_START_DECLARATION) }

        assertEquals(
            1,
            declarations.size,
            "`$REAL_LINE_START_DECLARATION` must be declared EXACTLY once in $RULE_OWNER, or the " +
                "value assertion below is reading one of several and proves nothing about the start " +
                "the composer actually uses.\n  Read as: $declarations",
        )

        val literal = declarations.single().substringAfter("=").trim()
        assertTrue(
            literal.length >= 2 && literal.startsWith("\"") && literal.endsWith("\""),
            "the initializer of `$REAL_LINE_START_DECLARATION` is not a plain string literal, so it " +
                "cannot be decoded here. Read as: $literal",
        )

        val decoded = decodeKotlinStringLiteral(literal)

        assertEquals(
            EXPECTED_REAL_LINE_START,
            decoded,
            "the real-line branch must start at a line anchor FOLLOWED BY a possessive run of " +
                "horizontal whitespace. A bare `^` here is the pre-27-17 state and it is a MEASURED " +
                "two-mode leak, not a style regression: `GET / HTTP/1.1\\r\\n Cookie: a=SECRET5` came " +
                "back BYTE-UNCHANGED from STRICT and from BALANCED, canonical header name and all, " +
                "while the un-indented control stripped in the same run. An obs-folded continuation " +
                "line leaks by the same mechanism. Dropping the `+` is a smaller regression but still " +
                "a real one — it re-admits the backtracking the possessive form was measured to " +
                "remove (200 scans of a 4000-space line: 29 ms possessive, 63 ms not), on rules that " +
                "run in the header stage with NO per-pattern deadline. Do NOT 'improve' this into " +
                "the zero-width lookbehind `(?<=^[ \\t]*)`: it compiles on Java 21 and it matches " +
                "correctly, and it was MEASURED at roughly 221x the cost of this spelling.\n" +
                "  Read as: $literal",
        )

        // Non-vacuity for the value itself: prove the decoded start behaves the way the constant
        // claims, rather than trusting a string comparison to carry a behavioural claim.
        val probe = Regex("(?im)" + decoded + "cookie:")
        assertTrue(probe.containsMatchIn("GET / HTTP/1.1\n Cookie: a=b"), "the decoded start does not match an indented header line")
        assertTrue(probe.containsMatchIn("GET / HTTP/1.1\n\tCookie: a=b"), "the decoded start does not match a TAB-indented header line")
        assertTrue(probe.containsMatchIn("GET / HTTP/1.1\nCookie: a=b"), "the decoded start no longer matches an UN-indented header line")
    }

    // ── the scans ─────────────────────────────────────────────────────────────────────────

    /**
     * The lines of one property's declaration, comment lines removed.
     *
     * Isolated BY NAME and BY INDENTATION rather than by counting parentheses: these declarations
     * concatenate regex fragments, and a string literal like `"(?!"` carries an unbalanced paren
     * that would derail a brace counter. A member of `object Redaction` is declared at one indent
     * level; its initializer is indented deeper; the block therefore ends at the next non-blank line
     * at or above the declaration's own indent.
     */
    private fun declarationBlockOf(propertyName: String): List<String> {
        val lines = sourceFile().readLines()
        val startIndex = lines.indexOfFirst { Regex("""^\s*private val $propertyName\s*[:=]""").containsMatchIn(it) }
        if (startIndex < 0) return emptyList()

        val declarationIndent = lines[startIndex].indentWidth()
        val initializer =
            lines
                .subList(startIndex + 1, lines.size)
                .takeWhile { it.isNotBlank() && it.indentWidth() > declarationIndent }
        return (listOf(lines[startIndex]) + initializer).filterNot { isCommentOnly(it) }
    }

    /**
     * The contiguous comment-and-blank region immediately above the first boundary fragment — the
     * prose a reader meets on their way to the composition, walking back to the first line of real
     * code above it.
     */
    private fun rationaleRegionAboveFragments(): List<String> {
        val lines = sourceFile().readLines()
        val fragmentIndex = lines.indexOfFirst { it.trimStart().startsWith(REQUIRED_DECLARATIONS.first()) }
        if (fragmentIndex < 0) return emptyList()

        var start = fragmentIndex
        while (start > 0) {
            val candidate = lines[start - 1]
            if (!candidate.isBlank() && !isCommentOnly(candidate)) break
            start--
        }
        return lines.subList(start, fragmentIndex).filter { isCommentOnly(it) }
    }

    /**
     * Decodes the body of a Kotlin string literal, covering exactly the TWO escapes a regex-fragment
     * constant of this kind can carry: an escaped double quote and an escaped backslash. Anything
     * else FAILS rather than being passed through — a decoder that silently ignores an escape it
     * does not know would compare the wrong value and go green.
     */
    private fun decodeKotlinStringLiteral(literal: String): String {
        val body = literal.removeSurrounding("\"")
        val decoded = StringBuilder()
        var index = 0
        while (index < body.length) {
            val character = body[index]
            if (character != '\\') {
                decoded.append(character)
                index++
                continue
            }
            when (val escaped = body.getOrNull(index + 1)) {
                '"' -> decoded.append('"')
                '\\' -> decoded.append('\\')
                else ->
                    throw AssertionError(
                        "unhandled Kotlin escape `\\$escaped` in $literal. Extend this decoder " +
                            "deliberately rather than loosening the value assertion that reads it.",
                    )
            }
            index += 2
        }
        return decoded.toString()
    }

    private fun String.indentWidth(): Int = length - trimStart().length

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    /**
     * Resolved through [SourceRoots.file] in whichever production root holds it. FAILS rather than skips:
     * a path in neither root, or in both, is an AssertionError naming the roots it looked at.
     */
    private fun sourceFile(): File = SourceRoots.file(RULE_OWNER)

    private companion object {
        const val RULE_OWNER = "com/six2dez/burp/aiagent/redact/Redaction.kt"

        /** Measured at 2018 lines. A floor, not a count. */
        const val MIN_EXPECTED_LINES = 1500

        const val COMPOSER_CALL = "logicalLineHeaderRule("

        /**
         * The MEASURED set of rules that carry the logical-line boundary. Plan 27-04 added the two
         * cookie rules; plan 27-05 (D-27-12) added `authHeaderRegex` on the measured evidence that a
         * plain-token `X-API-Key` value survived STRICT and BALANCED on the serialized shape.
         */
        val COMPOSED_RULES =
            listOf(
                "cookieHeaderRegex",
                "setCookieHeaderRegex",
                "authHeaderRegex",
            )

        /** The deliberate exclusion (D-27-13), carried as open finding AR-27-04 for plan 27-06. */
        const val EXCLUDED_RULE = "hostHeaderRegex"
        const val OPEN_FINDING = "AR-27-04"

        /**
         * The second residual (27-11), **CLOSED BY FIX at 27-17** rather than accepted at LOW.
         *
         * WHAT IT WAS: a header line preceded by leading horizontal whitespace, or an obs-folded
         * continuation, matched none of the three recognised starts. MEASURED surviving STRICT in
         * round 3, re-measured surviving STRICT *and* BALANCED at the end of round 4, and re-measured
         * a third time immediately before the fix.
         *
         * WHY IT WAS FIXED RATHER THAN ACCEPTED: the LOW rested on an explicitly UNMEASURED
         * reachability claim, which is the defect class that reopened this phase five times. The
         * maintainer decided it at UAT (`27-HUMAN-UAT.md` item 10).
         *
         * IT STAYS PINNED THOUGH IT IS CLOSED, and that is deliberate. The register entry and the
         * source state have to move together: a closure recorded only in a planning document is one
         * refactor away from a silent revert, and the rationale a reader meets would then describe a
         * boundary the code no longer has. What is pinned is the CITATION and the closure wording —
         * see [REAL_LINE_START_DECLARATION] for the pin on the VALUE that does the closing.
         */
        const val SECOND_FINDING_CLOSED_BY_FIX = "AR-27-09"

        /**
         * The wording that has to accompany [SECOND_FINDING_CLOSED_BY_FIX] in the rationale, so the
         * id cannot survive there as a stale "still open" sentence after the code stopped agreeing.
         */
        const val SECOND_FINDING_CLOSURE_MARKER = "CLOSED BY FIX"

        /**
         * The THIRD residual (27-14), with its BOUND CORRECTED after 27-REVIEW-3 CR-01 measured it
         * four times wider than this KDoc and the register both stated it.
         *
         * THE MECHANISM, not one example: [JSON_STRING_OPEN_DECLARATION]'s value is `:"`, the two
         * LITERAL characters colon then quote, so any shape that interposes a character between them
         * — a space, or the backslash of an escaped quote — and any shape with no colon before the
         * quote at all, is NOT a recognised start. FOUR families under this one id, every one of them
         * MEASURED matching under the bare quote 27-11 shipped and byte-unchanged under the narrowed
         * value, in STRICT and BALANCED alike, across all three composed rules:
         *
         *  1. a NESTED / ESCAPED string value open — `\"k\":\"Cookie: …` — which is what a captured
         *     RESPONSE BODY that is itself JSON looks like once it is serialized into a tool result,
         *     so this family sits on the PRIMARY MCP emission path;
         *  2. PRETTY-PRINTED JSON — `"k": "Cookie: …` — a space between the colon and the quote;
         *  3. a BARE TOP-LEVEL JSON string document — `"Cookie: …`;
         *  4. an ARRAY ELEMENT open — `["Cookie: …` and `,"Cookie: …` — the ONE family this KDoc
         *     named alone before the correction.
         *
         * In all four, only a header that is the FIRST CONTENT of its string escapes: one that
         * follows an escaped newline is still stripped. Filed at MEDIUM, raised from LOW when the
         * family list was corrected — see the `AR-27-11` row in `26-SECURITY.md` for the re-derivation.
         *
         * It is the residual the narrowing BOUGHT, and it is pinned here for the same reason
         * `AR-27-04` and `AR-27-09` are: a residual that lives only in a planning document is one
         * refactor away from disappearing. What is pinned is the CITATION, never the survival — a
         * green assertion that this cookie value survives a redacting policy is the artifact class
         * `26-SECURITY.md` standing-rule clause (vi) prohibits.
         */
        const val THIRD_OPEN_FINDING = "AR-27-11"

        /** The declaration [theJsonStringOpenIsAValueOpenAndNotABareQuote] reads the VALUE out of. */
        const val JSON_STRING_OPEN_DECLARATION = "private const val JSON_STRING_OPEN"

        /**
         * The declaration [theRealLineStartRecognisesLeadingHorizontalWhitespace] reads the VALUE out
         * of — the FOURTH logical line start, added at 27-17 to close `AR-27-09`.
         *
         * Pinned from source for the reason 27-14 had to learn the hard way with
         * [JSON_STRING_OPEN_DECLARATION]: asserting that a declaration EXISTS says nothing about what
         * it is worth, and reverting `^[ \t]*+` to `^` is a nine-character edit that would otherwise
         * put the measured two-mode leak back with every other guard in this file still green.
         */
        const val REAL_LINE_START_DECLARATION = "private const val REAL_LINE_START"

        // A lookbehind wider than a FIXED width forces Java to try two look-back widths at every
        // position of every serialized emission and silently trades away the measured 2.4x — the same
        // reason JSON_ESCAPED_NEWLINE's comment in Redaction.kt gives for its own two characters.
        const val EXPECTED_JSON_STRING_OPEN_WIDTH = 2

        /**
         * The FOURTH start, character for character: line anchor, then a POSSESSIVE run of horizontal
         * whitespace. Possessive is safe rather than merely fast — no composed name pattern can begin
         * with a space or a tab, so giving whitespace back could never enable a match the possessive
         * form misses — which is also why the widened start is a PROVEN strict superset of `^` and
         * therefore moves only in the over-redacting direction.
         */
        const val EXPECTED_REAL_LINE_START = "^[ \\t]*+"

        /**
         * The composer and the four fragments the boundary rationale is written against.
         *
         * ORDER IS LOAD-BEARING, and only for the FIRST element: `rationaleRegionAboveFragments`
         * anchors its walk-back on `REQUIRED_DECLARATIONS.first()`, so promoting a different
         * declaration to index 0 would move the anchor and change what [MIN_RATIONALE_LINES]
         * measures — silently, with nothing turning red. `private const val JSON_ESCAPED_NEWLINE`
         * stays first. New fragments are APPENDED, as `JSON_STRING_OPEN` was at 27-11.
         *
         * Nothing here may be REMOVED to make room, either. Each entry is a live guard, and the
         * composer entry — the only non-fragment in the list — is the one a "tidy-up" would reach
         * for first.
         */
        val REQUIRED_DECLARATIONS =
            listOf(
                "private const val JSON_ESCAPED_NEWLINE",
                "private const val REAL_LINE_HEADER_VALUE",
                "private const val JSON_ESCAPED_HEADER_VALUE",
                "private fun logicalLineHeaderRule",
                "private const val JSON_STRING_OPEN",
                "private const val REAL_LINE_START",
            )

        /**
         * A floor on the rationale region, so a one-line comment cannot pass as a stated bound.
         * MEASURED at 125 comment lines after plan 27-11 extended the region (78 before it). A
         * FLOOR, not a count — the same discipline as [MIN_EXPECTED_LINES] — so prose edits are free
         * while gutting the stated bounds turns red.
         */
        const val MIN_RATIONALE_LINES = 90
    }
}
