package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * (PRIV-05) Phase 28 plans 28-01 and 28-04 — `AR-27-08`, the issue-detail cookie carrier.
 *
 * PHASE 29 (D-16) — THIS FILE IS THE STORE HALF. The fourteen tests that measure the route through
 * the serialized `IssueDetails` blob (`IssueDetails` -> `toolJson` -> `Redaction.apply`) moved
 * verbatim to FullIssueDetailCookieCarrierTest: `toolJson` and the `mcp.schema` types belong to the
 * generic MCP tools, which only the full flavor packages, and so does the `scanner_issues` route
 * itself. That includes both designated red probes named below. The seven tests here read the
 * detail LINES or source text, which every build ships; the fixtures they do not use were dropped.
 * The KDoc below is kept whole, so a `[name]` reference may resolve in the Full twin.
 *
 * WHAT THIS FILE MEASURES. A COOKIE-typed [InjectionPoint]'s `originalValue` is written into
 * `AuditIssue.detail()` by `ActiveAiScanner.createConfirmedIssue`, and leaves the product over MCP
 * as `IssueDetails.detail` (`mcp/schema/Serialization.kt:14`, the `scanner_issues` tool result).
 * Phase 27 MEASURED that route and applied no control: the disposition was TRANSFER, not mitigate.
 * These tests are the control's proof, and they carry their own attribution control, their own
 * positive control and their own non-vacuity guard so that a green result here cannot be produced
 * by some other rule.
 *
 * TWO DETAIL LINES ARE COVERED, NOT ONE. Plan 28-01 controlled `Original Value:`. Plan 28-04
 * controls `Payload Used:` one line below it, because for a COOKIE point production DERIVES the
 * payload from the injection point's value — `ActiveAiScanner.kt:511-515` hands
 * `target.injectionPoint.originalValue` to `PayloadGenerator.generateContextAwarePayloads`, which
 * interpolates it with no injection-type filter — so that line re-leaked the exact bytes the line
 * above had just stripped. `28-VERIFICATION.md` measured SC1 FALSE on precisely that gap.
 *
 * WHAT THIS FILE STILL DOES NOT COVER, so a green run is not over-read. `AiScanCheck.buildDetail`
 * is a SECOND active-scan detail producer in the repository and nothing here can see it; plan 28-05
 * owns it. No assertion in this file is a repository-wide single-producer gate — `WR-01` measured
 * that framing as false and D-28-06 keeps the real gate as a named residual.
 *
 * WHY THE MEASURED ROUTE IS BLIND TO THE REDACTOR (from 27-08-SUMMARY.md, not re-derived here).
 * `IssueUtils.formatIssueDetailHtml` joins the detail lines with `<br>`, so the blob carries NO
 * newline and the logical-line cookie rules have nothing to bind to. The rendered shape is
 * `Original Value: <value>`, not `name=<value> (COOKIE)`, so `Redaction.cookieTypedParamRegex`
 * cannot key on it either. The enclosing JSON key is `detail`, which is absent from
 * `SENSITIVE_WORDS`. The control therefore has to go at the WRITE site, keyed on the
 * [InjectionType] enum — the type-keyed discipline `McpToolHelpers.sanitizeParameters` states for
 * the sibling parameter carrier — because the write site is the last point in the route that still
 * holds the type at all.
 *
 * MOCKS-FREE BY CONSTRUCTION. Nothing here touches Montoya. The fixtures are built from the REAL
 * serializer types plus `toolJson`, never from a hand-typed escaped JSON envelope, so if the
 * emitted shape changes these tests move with it instead of quietly asserting against a shape that
 * is no longer emitted.
 *
 * SENTINEL DISCIPLINE. Both sentinels are low-entropy hyphenated lowercase words: no digits, no
 * `=`, no `.`, no `Bearer `/`Basic ` prefix, no regex metacharacter. So no entropy rule, no token
 * rule, no secret-key rule and no parameter rule can plausibly claim either of them. That claim is
 * not left as prose — [urlParamOriginalValueSurvivesStrict_attributionControl] PROVES it by
 * carrying the IDENTICAL sentinel on a URL_PARAM-typed point through STRICT and asserting it
 * survives. If some unrelated rule were doing the removal, that test would go red with the others.
 *
 * THE TWO SENTINELS MUST BE DIFFERENT STRINGS, not merely different variables.
 * [POSITIVE_CONTROL_COOKIE_VALUE] and [DETAIL_SENTINEL] are checked distinct and non-overlapping
 * in [BeforeEach], before any test body runs. This is load-bearing and the collision it prevents is
 * INVISIBLE IN A DIFF: `ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER` and the header rule's
 * marker are BOTH the literal `[STRIPPED]`, so a shared sentinel would let one substitution rewrite
 * both occurrences and leave the whole-blob difference enumeration with nothing to attribute.
 *
 * ## THE DESIGNATED RED PROBE — read this before mutating the control
 *
 * ONE DESIGNATED PROBE PER CONTROL, so a mutation is attributable to the gate it broke. If you
 * weaken `ScannerIssueSupport.sanitizeRenderedPayload`'s cookie branch, the assertion that is
 * SUPPOSED to catch you is the first `assertFalse` in [cookiePayloadIsStrippedUnderStrict] —
 * 28-04's designated red probe, whose three mutations are recorded verbatim in `28-04-SUMMARY.md`.
 *
 * If you weaken `ScannerIssueSupport.sanitizeInjectionPointValue`'s cookie branch, the assertion
 * that is SUPPOSED to catch you is the first `assertFalse` in
 * [cookieOriginalValueIsStrippedUnderStrict]. It is the designated red probe for that control.
 * [cookieOriginalValueIsStrippedUnderBalanced] and [cookieOriginalValueSurvivesUnderOff] go red
 * alongside it and are not redundant: the OFF one catches the opposite mistake, a control that
 * fires unconditionally.
 *
 * MEASURED 2026-08-27 by negating the branch condition — 7 of the 14 tests went red. Every
 * assertion that reads the COOKIE carrier's value under a policy-determined mode moved; the other
 * seven stayed green because none of them does. The seven that are BLIND to that mutation, and
 * therefore prove nothing about this control on their own:
 * [sentinelsAreDistinctAndNonOverlapping] (a fixture guard over two constants),
 * [urlParamOriginalValueSurvivesStrict_attributionControl] (a non-COOKIE type, green by design —
 * that is what makes it an attribution control), [theCookieHeaderPositiveControlFiresInTheSameStrictOutput]
 * and [theRequestResponsesListIsNotAlteredByTheControl] (both read `requestResponses`, which this
 * control never touches), [theCookieNameSurvivesEveryMode] (reads the NAME),
 * [theOriginalValueBoundIsDerivedFromTheConstant] (a non-COOKIE type again) and
 * [theWriteSiteReadsTheLivePolicy] (asserts over a DIFFERENT file's source text).
 *
 * A SECOND MUTATION, MEASURED SEPARATELY, because the two catch different mistakes. Dropping the
 * `Payload Used` line whenever the cookie gate fires — an OVER-MATCH that eats content PAST the
 * control's span, the regression class phase 27 round 4 shipped — turned exactly
 * [theStrippedDetailFieldRetainsEverythingAfterTheControlPoint] and
 * [theOnlyThreeDifferencesBetweenStrictAndOffAreTheEnumeratedControls] red while EVERY leak-only
 * assertion in this file stayed green. That is the measured reason those two guards exist: an
 * absence assertion is structurally unable to see content destruction.
 *
 * WHAT THIS FILE CANNOT CATCH, stated so a reader does not over-read a green run. Every BEHAVIOURAL
 * test here calls `ScannerIssueSupport.buildActiveIssueDetailLines` DIRECTLY. Nothing here executes
 * `ActiveAiScanner.createConfirmedIssue`, so no behavioural assertion proves the operator's
 * configured privacy mode actually reaches the gate. MEASURED: hard-coding that call site's policy
 * argument to `RedactionPolicy.fromMode(PrivacyMode.OFF)` left ALL EIGHT behavioural tests then in
 * this file GREEN. [theWriteSiteReadsTheLivePolicy] was added for exactly that gap and is the only
 * assertion that catches it; it is the source-TEXT pin standing in for coverage this file does not
 * have, and it is weaker than an execution assertion in a way the residual section of
 * `28-01-SUMMARY.md` names explicitly.
 */
class IssueDetailCookieCarrierTest {
    @BeforeEach
    fun clearCustomPatternsAndCheckSentinels() {
        // Redaction is a singleton object: custom patterns left behind by another test class in the
        // same JVM would bleed in here and could remove a sentinel for the wrong reason, letting an
        // absence assertion pass without the new control doing anything. Precedent:
        // SerializedEmissionRedactionTest.
        Redaction.setCustomPatterns(emptyList())
        assertSentinelsAreDistinctAndNonOverlapping()
    }

    @Test
    fun sentinelsAreDistinctAndNonOverlapping() {
        // Named as a test as well as run from @BeforeEach, so the guard is visible in a test report
        // rather than only in a setup method a reader has to go looking for.
        assertSentinelsAreDistinctAndNonOverlapping()
    }

    /**
     * The source-TEXT pin standing in for the execution coverage this file does NOT have.
     *
     * WHY IT EXISTS. Mutation B of 28-01's red probe — hard-coding the write site's policy argument
     * to a constant instead of reading the operator's setting — was MEASURED as undetected: all 8
     * behavioural tests stayed green. That is a real gap in this file's reach, not a hypothetical.
     *
     * WHAT IT CANNOT SEE, stated rather than left for a reader to discover. This asserts over source
     * TEXT. A refactor that keeps the literal `RedactionPolicy.fromMode(getSettings().privacyMode)`
     * on the page while routing a different policy object into the call passes this pin unchanged.
     * It is kept anyway because it is non-vacuous TODAY: that file's comment-stripped
     * `RedactionPolicy.fromMode(` count was DERIVED as 0 before this phase, so requiring exactly 1
     * measures a change this phase makes rather than restating a constant.
     */
    @Test
    fun theWriteSiteReadsTheLivePolicy() {
        val executableLines =
            activeScannerSource()
                .lines()
                .filterNot { it.trimStart().startsWith("//") }
                .filterNot { it.trimStart().startsWith("*") }
                .filterNot { it.trimStart().startsWith("/*") }

        val fromModeLines = executableLines.filter { it.contains("RedactionPolicy.fromMode(") }

        assertEquals(
            1,
            fromModeLines.size,
            "PIN: `$ACTIVE_SCANNER_SOURCE_PATH` must contain EXACTLY ONE executable " +
                "`RedactionPolicy.fromMode(` occurrence — the write site's policy lookup. Found " +
                "${fromModeLines.size}: $fromModeLines",
        )
        assertTrue(
            fromModeLines[0].contains("RedactionPolicy.fromMode(getSettings().privacyMode)"),
            "PIN: the write site must derive its policy from the OPERATOR'S LIVE SETTING, not from a " +
                "constant. Expected the argument text `getSettings().privacyMode`, found: " +
                "`${fromModeLines[0].trim()}`",
        )
    }

    /**
     * Standing rule (vi): where a number is source-derivable a test must DERIVE it. The two prose
     * counts that drifted last round drifted inside a single commit.
     */
    @Test
    fun theOriginalValueBoundIsDerivedFromTheConstant() {
        // A NON-cookie type on purpose: the bound is the PASS-THROUGH branch's behaviour, and
        // reading it on a cookie point under a stripping mode would measure the marker instead.
        val overshoot = ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS + BOUND_OVERSHOOT_CHARS
        val filler = FILLER_UNIT.repeat(overshoot / FILLER_UNIT.length + 1).take(overshoot)
        val point = InjectionPoint(InjectionType.URL_PARAM, COOKIE_POINT_NAME, filler)

        val rendered = originalValueRenderedFor(point, PrivacyMode.OFF)

        assertEquals(
            ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS,
            rendered.length,
            "BOUND: the Original Value line's value part must be truncated to exactly " +
                "ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS " +
                "(${ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS}) characters. The input was " +
                "$overshoot characters and rendered as ${rendered.length}. This expectation is READ " +
                "FROM the constant and must never be restated as a literal.",
        )
    }

    /**
     * The marker must not be run through the truncation bound and emerge as a fragment. A truncated
     * marker still reads as "stripped" to a human while defeating every assertion that matches the
     * whole marker.
     */
    @Test
    fun theStrippedMarkerIsNotTruncated() {
        val rendered = originalValueRenderedFor(cookiePoint(), PrivacyMode.STRICT)

        assertEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            rendered,
            "MARKER INTEGRITY: the COOKIE carrier's Original Value line must render the stripped " +
                "marker EXACTLY, not a prefix of it. Rendered: '$rendered'.",
        )
    }

    /**
     * The payload line's twin of [theStrippedMarkerIsNotTruncated]. A marker run through
     * [ScannerIssueSupport.PAYLOAD_VALUE_MAX_CHARS] and emerging as a fragment still reads as
     * "stripped" to a human while defeating every assertion that matches the whole marker.
     */
    @Test
    fun thePayloadStrippedMarkerIsNotTruncated() {
        val rendered = payloadRenderedFor(cookiePoint(), PrivacyMode.STRICT)

        assertEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            rendered,
            "MARKER INTEGRITY: the COOKIE carrier's '$PAYLOAD_USED_PREFIX' line must render the " +
                "stripped marker EXACTLY, not a prefix of it and not the marker with a residual " +
                "payload suffix attached. Rendered: '$rendered'.",
        )
    }

    /**
     * [edge:encoding] WHOSE DEFINITION OF EQUALITY APPLIES? NONE — and that is the point.
     *
     * The shape-keyed alternative D-28-07 rejected would search `payload.value` for the raw value
     * and excise it. This payload carries the value only percent-encoded, so that search finds
     * nothing and the leak ships. The type-keyed gate never reads the text, so it strips this one
     * exactly as it strips the raw-form payload.
     */
    @Test
    fun aCookiePayloadCarryingOnlyAnEncodedFormOfTheValueIsStillStripped() {
        // FIXTURE PREMISE, PINNED BEFORE IT IS USED. If the encoded form ever contained the raw
        // sentinel, this test would silently degrade into a duplicate of the STRICT test above.
        assertFalse(
            ENCODED_ONLY_PAYLOAD.value.contains(DETAIL_SENTINEL),
            "FIXTURE: the encoded-only payload must NOT contain the RAW sentinel " +
                "'$DETAIL_SENTINEL'; otherwise it measures nothing this file does not already " +
                "measure. Payload was '${ENCODED_ONLY_PAYLOAD.value}'.",
        )
        assertTrue(
            ENCODED_ONLY_PAYLOAD.value.contains(ENCODED_DETAIL_SENTINEL),
            "FIXTURE: the encoded-only payload must contain the TRANSFORMED sentinel " +
                "'$ENCODED_DETAIL_SENTINEL' — that transformed form IS the operator's value and is " +
                "what a shape-keyed control would miss. Payload was '${ENCODED_ONLY_PAYLOAD.value}'.",
        )

        val rendered = payloadRenderedFor(cookiePoint(), PrivacyMode.STRICT, ENCODED_ONLY_PAYLOAD)

        assertEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            rendered,
            "STRICT / [edge:encoding]: a COOKIE point's payload must be replaced by " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' whatever its TEXT looks " +
                "like. This payload carries the value only as '$ENCODED_DETAIL_SENTINEL'. Rendering " +
                "'$rendered' means the gate is reading the payload's text instead of the point's " +
                "TYPE — the shape-keyed mechanism D-28-07 rejected and phase 27 measured as " +
                "structurally blind.",
        )
    }

    /**
     * [edge:empty] The gate is keyed on the TYPE and never on the value being non-empty. The
     * `28-REVIEW.md` `CR-01` sketch carried an `isNotEmpty()` guard; under it, an empty-valued
     * cookie point would render a bare prefix and pass straight through both controls.
     */
    @Test
    fun anEmptyValuedCookiePointStillRendersTheMarkerOnBothLines() {
        val point = emptyValuedCookiePoint()

        listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED).forEach { mode ->
            assertEquals(
                ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
                originalValueRenderedFor(point, mode),
                "$mode / [edge:empty]: a COOKIE point whose originalValue is the EMPTY STRING must " +
                    "still render '${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' on the " +
                    "'$ORIGINAL_VALUE_PREFIX' line. An emptiness guard on the gate would render an " +
                    "empty value here and leak the TYPE's presence as an observable difference.",
            )
            assertEquals(
                ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
                payloadRenderedFor(point, mode),
                "$mode / [edge:empty]: a COOKIE point whose originalValue is the EMPTY STRING must " +
                    "still render '${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' on the " +
                    "'$PAYLOAD_USED_PREFIX' line. The payload gate reads `point.type` only; adding " +
                    "an emptiness guard to it is the CR-01 sketch's defect, not an optimisation.",
            )
        }
    }

    /**
     * Resolved through [SourceRoots.file], which fails naming both production roots rather than letting a
     * missing or duplicated file surface as a bare FileNotFoundException.
     */
    private fun activeScannerSource(): String = SourceRoots.file(ACTIVE_SCANNER_SOURCE_PATH).readText()

    private fun assertSentinelsAreDistinctAndNonOverlapping() {
        assertNotEquals(
            DETAIL_SENTINEL,
            POSITIVE_CONTROL_COOKIE_VALUE,
            "FIXTURE: the positive-control cookie header value and the detail sentinel must be " +
                "DIFFERENT STRINGS. Sharing one makes the whole-blob difference enumeration red on " +
                "arrival for a fixture reason rather than a code reason.",
        )
        assertFalse(
            DETAIL_SENTINEL.contains(POSITIVE_CONTROL_COOKIE_VALUE) ||
                POSITIVE_CONTROL_COOKIE_VALUE.contains(DETAIL_SENTINEL),
            "FIXTURE: neither sentinel may contain the other. A substring relation defeats an " +
                "absence assertion exactly as a duplicate does.",
        )

        // [edge:adjacency], the CONTAINMENT half — 28-04. The two relations below are deliberate and
        // OPPOSITE: the payload must CONTAIN the detail sentinel, and must NOT overlap the
        // positive-control cookie value. Asserting only distinctness (above) would leave the payload
        // free to drift into either an accidental equality or an accidental overlap, and either one
        // makes an absence assertion over the payload line pass for the wrong reason.
        assertTrue(
            PAYLOAD.value.contains(DETAIL_SENTINEL),
            "FIXTURE / NON-VACUITY: the payload fixture is DERIVED at construction time from " +
                "`PayloadGenerator().generateContextAwarePayloads(VulnClass.SQLI, DETAIL_SENTINEL, " +
                "$DERIVED_PAYLOAD_LIMIT)` and MUST CONTAIN the sentinel '$DETAIL_SENTINEL'. It " +
                "rendered as '${PAYLOAD.value}'. A PayloadGenerator that stops interpolating the " +
                "original value would otherwise leave every payload assertion in this class " +
                "VACUOUSLY GREEN — an absence assertion over a payload that never carried the " +
                "sentinel proves nothing about the '$PAYLOAD_USED_PREFIX' line. That exact vacuity " +
                "is what `28-VERIFICATION.md` missing[3] measured in the hand-typed fixture this " +
                "one replaced.",
        )
        assertFalse(
            PAYLOAD.value.contains(POSITIVE_CONTROL_COOKIE_VALUE),
            "FIXTURE: the derived payload must NOT overlap the positive-control cookie value " +
                "'$POSITIVE_CONTROL_COOKIE_VALUE'. An overlap would let the PRE-EXISTING header " +
                "rule's substitution account for a change inside `detail` and make this plan's " +
                "control unattributable. Payload was '${PAYLOAD.value}'.",
        )
    }

    private companion object {
        /**
         * The value carried by the injection point and written into the detail blob. Low-entropy
         * hyphenated words: no digits, no `=`, no metacharacters, so only the new type gate can
         * plausibly remove it. Deliberately does NOT contain the token `cookie`, so no
         * header-name rule can bind to it even if a future boundary composer widens.
         */
        const val DETAIL_SENTINEL = "apple-orange-basket-lantern"

        /**
         * The POSITIVE CONTROL: the value of a real `Cookie:` header inside the same object's
         * `requestResponses`. Unrelated to [DETAIL_SENTINEL] by construction — see the class KDoc
         * for why sharing one would be silent.
         */
        const val POSITIVE_CONTROL_COOKIE_VALUE = "harbor-pebble-window-thistle"

        /** The injection point's NAME. Names survive every mode; values do not. */
        const val COOKIE_POINT_NAME = "pumpkin-lantern-name"

        /**
         * First line of the metadata section, used as the non-vacuity tail marker. Low-entropy, no
         * dots, no digits: nothing another redaction rule can plausibly claim, so its presence in
         * the tail measures the FIXTURE's shape rather than some rule's behaviour.
         */
        const val METADATA_SECTION_MARKER = "Backend: test-backend"

        /** The rendered prefix of the detail line 28-01's control owns. */
        const val ORIGINAL_VALUE_PREFIX = "Original Value: "

        /** The rendered prefix of the detail line 28-04's control owns — route 1 of `AR-27-08`. */
        const val PAYLOAD_USED_PREFIX = "Payload Used: "

        /** How far past [ScannerIssueSupport.ORIGINAL_VALUE_MAX_CHARS] the bound fixture overshoots. */
        const val BOUND_OVERSHOOT_CHARS = 25

        /** Repeating filler for the bound fixture. No digits, no dots, no metacharacters. */
        const val FILLER_UNIT = "filler-"

        val METADATA_SECTION = "$METADATA_SECTION_MARKER\r\nScan: Active\r\nConfidence: 90"

        const val ACTIVE_SCANNER_SOURCE_PATH = "com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt"

        /** How many payloads the derived fixture asks `PayloadGenerator` for. */
        const val DERIVED_PAYLOAD_LIMIT = 5

        /**
         * (PRIV-05) 28-04 / `CR-01` — the payload the detail lines render, DERIVED FROM PRODUCTION
         * rather than hand-typed.
         *
         * `28-VERIFICATION.md` `missing[3]` measured the previous HAND-TYPED value — a fixed probe
         * string that contradicted its own `VulnClass.SQLI` label — as the reason 14 green tests
         * said NOTHING about the `Payload Used:` line: it carried no trace of the injection point's
         * value, so no assertion over the blob could tell a controlled payload line from an
         * uncontrolled one. That literal is deliberately not repeated here. Production
         * builds a COOKIE point's payload by INTERPOLATING the cookie value
         * (`ActiveAiScanner.kt:511-515` passes `target.injectionPoint.originalValue` into
         * `PayloadGenerator.generateContextAwarePayloads`, which interpolates it at
         * `PayloadGenerator.kt:782`), so the fixture is built the SAME WAY, through the same pure
         * function — it touches no `ScanKnowledgeBase` and no singleton, so this stays mocks-free.
         *
         * [assertSentinelsAreDistinctAndNonOverlapping] asserts this value CONTAINS
         * [DETAIL_SENTINEL]. A generator that stops interpolating turns that guard red instead of
         * silently restoring the blind fixture.
         *
         * The `detectionMethod` is `BLIND_BOOLEAN` here where the hand-typed fixture said
         * `REFLECTION`, because that is what the string-context SQLI arm actually emits. The
         * `Detection Method:` detail line's text changes accordingly; that is the production truth
         * arriving in the fixture, not a regression.
         */
        val PAYLOAD =
            PayloadGenerator()
                .generateContextAwarePayloads(VulnClass.SQLI, DETAIL_SENTINEL, DERIVED_PAYLOAD_LIMIT)
                .first()

        /**
         * [edge:encoding] The sentinel in TRANSFORMED form: every `-` percent-encoded as `%2D`.
         *
         * Derived from [DETAIL_SENTINEL] rather than typed, so a sentinel change cannot leave this
         * silently unrelated to it. The raw sentinel is NOT a substring of the result.
         */
        val ENCODED_DETAIL_SENTINEL = DETAIL_SENTINEL.replace("-", "%2D")

        /**
         * [edge:encoding] A payload that carries the cookie value ONLY in encoded form.
         *
         * This is the fixture that answers "whose definition of equality applies?" with NONE. A
         * shape-keyed control — the substring-excision alternative D-28-07 REJECTED — would search
         * `payload.value` for the raw value, find nothing, and pass the payload through untouched.
         * The type-keyed gate never reads the text at all, so it strips this exactly as it strips
         * the raw-form payload.
         */
        val ENCODED_ONLY_PAYLOAD =
            Payload(
                value = "$ENCODED_DETAIL_SENTINEL' AND '1'='1",
                vulnClass = VulnClass.SQLI,
                detectionMethod = DetectionMethod.BLIND_BOOLEAN,
                risk = PayloadRisk.SAFE,
                expectedEvidence = "evidence-marker-present",
            )

        fun cookiePoint() = InjectionPoint(InjectionType.COOKIE, COOKIE_POINT_NAME, DETAIL_SENTINEL)

        /**
         * [edge:empty] A COOKIE point whose value is the EMPTY STRING.
         *
         * The gate is keyed on the TYPE, never on the value being non-empty, so this point must
         * still render the marker on both controlled lines. The `CR-01` sketch in `28-REVIEW.md`
         * carried an emptiness guard; it was rejected precisely because it would let this point
         * through.
         */
        fun emptyValuedCookiePoint() = InjectionPoint(InjectionType.COOKIE, COOKIE_POINT_NAME, "")

        fun detailLinesFor(
            point: InjectionPoint,
            mode: PrivacyMode,
            payload: Payload = PAYLOAD,
        ): List<String> =
            ScannerIssueSupport.buildActiveIssueDetailLines(
                point,
                VulnClass.SQLI.name,
                payload,
                "evidence-marker-present",
                METADATA_SECTION,
                RedactionPolicy.fromMode(mode),
            )

        /**
         * The rendered value part of the one `Original Value: ` line, read from the detail LINES
         * rather than from the serialized blob so the bound and the marker can be measured without
         * a redaction pass standing between the assertion and the thing it measures.
         */
        fun originalValueRenderedFor(
            point: InjectionPoint,
            mode: PrivacyMode,
        ): String {
            val matching = detailLinesFor(point, mode).filter { it.contains(ORIGINAL_VALUE_PREFIX) }
            assertEquals(
                1,
                matching.size,
                "SINGLE PRODUCER: exactly one detail line may carry the '$ORIGINAL_VALUE_PREFIX' " +
                    "prefix. Found ${matching.size}: $matching. A second producer is how this " +
                    "control gets bypassed without anyone editing it.",
            )
            return matching[0].substringAfter(ORIGINAL_VALUE_PREFIX)
        }

        /**
         * (PRIV-05) 28-04 — the twin of [originalValueRenderedFor] for the `Payload Used: ` line.
         *
         * ITS REACH, STATED HONESTLY RATHER THAN INHERITED. The sibling helper frames its
         * `assertEquals(1, ...)` as a repository-wide SINGLE PRODUCER gate. `28-REVIEW.md` `WR-01`
         * MEASURED that framing as false — the assertion filters the list
         * `buildActiveIssueDetailLines` itself returned and is structurally incapable of seeing a
         * producer in another file — so this helper does not repeat it. D-28-06 keeps the
         * repository-wide gate as a NAMED RESIDUAL that this round deliberately does not build.
         */
        fun payloadRenderedFor(
            point: InjectionPoint,
            mode: PrivacyMode,
            payload: Payload = PAYLOAD,
        ): String {
            val matching = detailLinesFor(point, mode, payload).filter { it.contains(PAYLOAD_USED_PREFIX) }
            assertEquals(
                1,
                matching.size,
                "ONE LINE PER CALL: exactly one line of the list `buildActiveIssueDetailLines` " +
                    "RETURNED may carry the '$PAYLOAD_USED_PREFIX' prefix. Found ${matching.size}: " +
                    "$matching. This assertion's reach is exactly that list and no wider: it CANNOT " +
                    "see a second detail-line producer in another file, and at this commit " +
                    "`AiScanCheck.buildDetail` is one (plan 28-05 owns it). Do not read a green " +
                    "result here as a repository-wide single-producer guarantee — D-28-06 records " +
                    "that gate as a residual this round did not build.",
            )
            return matching[0].substringAfter(PAYLOAD_USED_PREFIX)
        }
    }
}
