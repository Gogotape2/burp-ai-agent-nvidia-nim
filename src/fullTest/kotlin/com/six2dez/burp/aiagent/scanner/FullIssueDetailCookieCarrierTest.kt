package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.mcp.schema.AuditIssueConfidence
import com.six2dez.burp.aiagent.mcp.schema.AuditIssueDefinition
import com.six2dez.burp.aiagent.mcp.schema.AuditIssueSeverity
import com.six2dez.burp.aiagent.mcp.schema.HttpRequestResponse
import com.six2dez.burp.aiagent.mcp.schema.HttpService
import com.six2dez.burp.aiagent.mcp.schema.IssueDetails
import com.six2dez.burp.aiagent.mcp.tools.toolJson
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.util.IssueUtils
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * (PRIV-05) Phase 28 plans 28-01 and 28-04 — `AR-27-08`, the issue-detail cookie carrier.
 *
 * PHASE 29 (D-16) — THIS FILE IS THE FULL HALF, split verbatim out of IssueDetailCookieCarrierTest.
 * Its fourteen tests measure the route through the serialized `IssueDetails` blob (`IssueDetails`
 * -> `toolJson` -> `Redaction.apply`), and `toolJson` and the `mcp.schema` types belong to the
 * generic MCP tools, which only the full flavor packages. The seven tests that read the detail LINES
 * or source text stayed in IssueDetailCookieCarrierTest; the fixtures only they use were dropped
 * here. The KDoc below is the original, kept whole: its `[name]` references resolve across the two.
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
class FullIssueDetailCookieCarrierTest {
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
    fun cookieOriginalValueIsStrippedUnderStrict() {
        val output = redactedBlobFor(cookiePoint(), PrivacyMode.STRICT)

        assertFalse(
            output.contains(DETAIL_SENTINEL),
            "STRICT: the COOKIE-typed injection point's originalValue must be ABSENT from the " +
                "serialized issue detail, but the sentinel '$DETAIL_SENTINEL' was present.",
        )
        assertTrue(
            output.contains("Original Value: ${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "STRICT: the COOKIE carrier's Original Value line must render the stripped marker " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}', but it did not.",
        )
    }

    @Test
    fun cookieOriginalValueIsStrippedUnderBalanced() {
        val output = redactedBlobFor(cookiePoint(), PrivacyMode.BALANCED)

        assertFalse(
            output.contains(DETAIL_SENTINEL),
            "BALANCED: the COOKIE-typed injection point's originalValue must be ABSENT from the " +
                "serialized issue detail, but the sentinel '$DETAIL_SENTINEL' was present.",
        )
        assertTrue(
            output.contains("Original Value: ${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "BALANCED: the COOKIE carrier's Original Value line must render the stripped marker " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}', but it did not.",
        )
    }

    @Test
    fun cookieOriginalValueSurvivesUnderOff() {
        val output = redactedBlobFor(cookiePoint(), PrivacyMode.OFF)

        assertTrue(
            output.contains(DETAIL_SENTINEL),
            "OFF: the COOKIE-typed injection point's originalValue must be PRESENT verbatim in the " +
                "serialized issue detail, but the sentinel '$DETAIL_SENTINEL' was missing — the " +
                "control is policy-driven, not an unconditional rewrite.",
        )
        assertFalse(
            output.contains(ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER),
            "OFF: the stripped marker must NOT appear anywhere in the blob; its presence would mean " +
                "some control fired in the mode that is defined as applying none.",
        )

        // NON-VACUITY. The sentinel must not be the last token of the blob: content has to follow it
        // so the value's tail — the region a too-greedy control eats — is genuinely exercised. This
        // is the vacuity class that let a content-destruction regression ship in phase 27 round 4.
        val tail = output.substringAfter(DETAIL_SENTINEL)
        assertTrue(
            tail.isNotEmpty() && tail.contains("requestResponses"),
            "OFF: content must follow the sentinel in the serialized blob (non-vacuity), but the " +
                "tail after '$DETAIL_SENTINEL' was ${tail.length} chars and did not reach " +
                "requestResponses.",
        )
    }

    @Test
    @Suppress("ktlint:standard:function-naming")
    fun urlParamOriginalValueSurvivesStrict_attributionControl() {
        val output = redactedBlobFor(urlParamPoint(), PrivacyMode.STRICT)

        assertTrue(
            output.contains(DETAIL_SENTINEL),
            "STRICT / ATTRIBUTION: the IDENTICAL sentinel carried by a URL_PARAM-typed injection " +
                "point must SURVIVE, proving the COOKIE result is caused by the new type gate and " +
                "not by an entropy, token or sensitive-key rule that happens to match " +
                "'$DETAIL_SENTINEL'. It was absent, so the COOKIE assertions above are not " +
                "attributable to this control.",
        )
    }

    @Test
    fun theCookieHeaderPositiveControlFiresInTheSameStrictOutput() {
        val output = redactedBlobFor(cookiePoint(), PrivacyMode.STRICT)

        assertFalse(
            output.contains(POSITIVE_CONTROL_COOKIE_VALUE),
            "STRICT / POSITIVE CONTROL: the real Cookie: header value inside requestResponses[0] " +
                "must be stripped in the SAME output, but '$POSITIVE_CONTROL_COOKIE_VALUE' was " +
                "present — the pre-existing header rule did not fire, so this output proves nothing.",
        )
        assertTrue(
            output.contains("Cookie: [STRIPPED]"),
            "STRICT / POSITIVE CONTROL: the pre-existing cookie header rule must render " +
                "'Cookie: [STRIPPED]' in the SAME output, reproducing 27-08 measurement 2's control.",
        )
    }

    @Test
    fun theCookieNameSurvivesEveryMode() {
        PrivacyMode.entries.forEach { mode ->
            val output = redactedBlobFor(cookiePoint(), mode)
            assertTrue(
                output.contains(COOKIE_POINT_NAME),
                "$mode: the cookie NAME on the Injection Point line must survive — the requirement " +
                    "forbids values, not names — but '$COOKIE_POINT_NAME' was absent.",
            )
        }
    }

    @Test
    fun theRequestResponsesListIsNotAlteredByTheControl() {
        // D-28-01's accepted trade, converted from a claim in prose into a checked invariant: the
        // operator keeps the raw value byte-for-byte in Burp's own request pane, because the control
        // rewrites the OUTBOUND rendering only and never touches the AuditIssue's requestResponses.
        // Read BEFORE serialization on purpose — this is the local-evidence question, not the
        // emission question.
        val details = issueDetailsFor(cookiePoint(), PrivacyMode.STRICT)
        val request = details.requestResponses[0].request

        assertTrue(
            request != null && request.contains(POSITIVE_CONTROL_COOKIE_VALUE),
            "LOCAL EVIDENCE: the AuditIssue's requestResponses entry must still carry " +
                "'$POSITIVE_CONTROL_COOKIE_VALUE' byte-for-byte before serialization, so the " +
                "operator retains the raw value in Burp's UI.",
        )
    }

    /**
     * The fixture-shape guard. A sentinel sitting at the very END of the serialized blob would let
     * every stripping assertion above pass whether or not the value's TAIL is handled, because
     * nothing follows it to be damaged. Phase 27 round 4 shipped a regression through exactly that
     * shape, so the shape itself is asserted rather than assumed.
     */
    @Test
    @Suppress("ktlint:standard:function-naming")
    fun theSentinelIsNotTheTailOfTheSerializedBlob_nonVacuity() {
        // OFF is the mode in which the sentinel is present BY DESIGN, so it is the only mode in
        // which the fixture's shape can be measured at all.
        val output = redactedBlobFor(cookiePoint(), PrivacyMode.OFF)
        val sentinelIndex = output.indexOf(DETAIL_SENTINEL)

        assertTrue(
            sentinelIndex >= 0,
            "NON-VACUITY: the sentinel '$DETAIL_SENTINEL' must be PRESENT in the OFF blob before " +
                "its position can be measured at all. It was absent, so this guard would otherwise " +
                "pass vacuously over an empty tail.",
        )

        val tail = output.substring(sentinelIndex + DETAIL_SENTINEL.length)

        assertTrue(
            tail.isNotEmpty() &&
                tail.contains(METADATA_SECTION_MARKER) &&
                tail.contains(POSITIVE_CONTROL_HEADER_BEFORE),
            "NON-VACUITY: the fixture has degenerated into the round-4 vacuity shape. The sentinel " +
                "is at or near the TAIL of the serialized blob, so nothing follows it to be damaged " +
                "and every stripping assertion in this class is therefore UNINFORMATIVE about the " +
                "value's tail — the region a too-greedy control eats. The tail after the sentinel " +
                "was ${tail.length} chars; it must reach BOTH the metadata marker " +
                "'$METADATA_SECTION_MARKER' (found: ${tail.contains(METADATA_SECTION_MARKER)}) and " +
                "the positive-control header '$POSITIVE_CONTROL_HEADER_BEFORE' (found: " +
                "${tail.contains(POSITIVE_CONTROL_HEADER_BEFORE)}). Restore content after the " +
                "sentinel; do not relax this assertion.",
        )
    }

    /**
     * THE CONTENT-DESTRUCTION GUARD. A leak-only assertion cannot see an over-match that ate
     * content PAST its intended span — the previous round's shipped regression was exactly that —
     * so this asserts an EQUALITY under one known substitution rather than an absence.
     *
     * SCOPED TO THE `detail` FIELD, NOT TO THE WHOLE BLOB, and the scoping is load-bearing. Task 1
     * deliberately places the positive-control `Cookie:` header inside `requestResponses[0].request`
     * of the SAME serialized object, and [theCookieHeaderPositiveControlFiresInTheSameStrictOutput]
     * REQUIRES that header to be stripped under STRICT. That stripped header sits AFTER the detail
     * sentinel in the same serialized string, so the OFF blob's tail is provably NOT present in the
     * STRICT blob and a whole-blob form of this guard would be red on arrival for a SPECIFICATION
     * reason rather than a code reason. The cheapest repair for a guard that is red on arrival is to
     * relax it until it no longer detects an over-match, which is how round 4 shipped its
     * regression. Scope it; do not weaken it; do not delete it.
     */
    @Test
    fun theStrippedDetailFieldRetainsEverythingAfterTheControlPoint() {
        val offDetail = detailFieldOf(redactedBlobFor(cookiePoint(), PrivacyMode.OFF))
        val strictDetail = detailFieldOf(redactedBlobFor(cookiePoint(), PrivacyMode.STRICT))

        // EXTRACTOR PIN, BEFORE ANY COMPARISON. An extractor that silently returned "" would make
        // the equality below compare two empty strings and pass while measuring nothing at all.
        assertTrue(
            offDetail.isNotBlank(),
            "EXTRACTOR: the OFF-mode `detail` field extracted from the redacted blob was blank. The " +
                "guard below would compare two empty strings and pass while measuring nothing.",
        )
        assertTrue(
            offDetail.contains(DETAIL_SENTINEL),
            "EXTRACTOR: the OFF-mode `detail` field must contain the sentinel '$DETAIL_SENTINEL'. " +
                "It did not, so the extractor is reading the wrong field and the guard below is " +
                "vacuous. Extracted: '$offDetail'",
        )
        // THIRD PIN, added by 28-04 alongside the payload substitution it protects. An extractor
        // that silently returned a SHORTER field would make that substitution match nothing, turn
        // it into a no-op, and leave the equality below passing while measuring one control instead
        // of two.
        assertTrue(
            offDetail.contains("$PAYLOAD_USED_PREFIX${PAYLOAD.value}"),
            "EXTRACTOR: the OFF-mode `detail` field must contain the rendered payload line " +
                "'$PAYLOAD_USED_PREFIX${PAYLOAD.value}'. It did not, so the payload substitution in " +
                "the prediction below matches nothing and the equality measures only the " +
                "original-value control. Extracted: '$offDetail'",
        )

        val expected = withDetailLineControlsApplied(offDetail)

        assertEquals(expected, strictDetail, contentDestructionMessage(expected, strictDetail))
    }

    /**
     * At the WHOLE-blob level the STRICT and OFF outputs differ in exactly THREE places, and all
     * three are named here rather than tolerated as a diff of unknown shape. A FOURTH difference is
     * a finding.
     *
     * The count went from two to three in 28-04, when the `Payload Used:` line acquired its own
     * control. The enumeration is deliberately a LIST OF NAMED CLAUSES rather than a tolerance: each
     * difference states which side moved and which mechanism moved it, so a green run attributes
     * every byte of divergence to a control someone chose.
     */
    @Test
    fun theOnlyThreeDifferencesBetweenStrictAndOffAreTheEnumeratedControls() {
        val offBlob = redactedBlobFor(cookiePoint(), PrivacyMode.OFF)
        val strictBlob = redactedBlobFor(cookiePoint(), PrivacyMode.STRICT)
        val strictDetail = detailFieldOf(strictBlob)
        val strictRequest = requestFieldOf(strictBlob)

        // DIFFERENCE 1, inside `detail` — THIS plan's control.
        assertTrue(
            detailFieldOf(offBlob).contains(DETAIL_SENTINEL) &&
                strictDetail.contains(ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER) &&
                !strictDetail.contains(DETAIL_SENTINEL),
            "DIFFERENCE 1 — THIS PLAN'S CONTROL, inside `detail` — did not occur as specified. The " +
                "sentinel '$DETAIL_SENTINEL' must be present in the OFF `detail` and replaced by " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' in the STRICT `detail`. " +
                "The new control is the side that moved.",
        )

        // DIFFERENCE 2, inside requestResponses[0].request — the PRE-EXISTING header rule. Not this
        // plan's control; its firing is what makes the null result inside `detail` attributable.
        assertTrue(
            requestFieldOf(offBlob).contains(POSITIVE_CONTROL_HEADER_BEFORE) &&
                strictRequest.contains(POSITIVE_CONTROL_HEADER_AFTER) &&
                !strictRequest.contains(POSITIVE_CONTROL_COOKIE_VALUE),
            "DIFFERENCE 2 — THE PRE-EXISTING HEADER RULE, inside requestResponses[0].request — did " +
                "not occur as specified. '$POSITIVE_CONTROL_HEADER_BEFORE' must be present in the " +
                "OFF request and rewritten to '$POSITIVE_CONTROL_HEADER_AFTER' in the STRICT " +
                "request. The PRE-EXISTING rule is the side that moved, not this plan's control.",
        )

        // DIFFERENCE 3, inside `detail` — 28-04's control on the `Payload Used:` line, route 1 of
        // `AR-27-08`. It is a difference in its OWN right and not a consequence of DIFFERENCE 1: for
        // a COOKIE point production DERIVES the payload from the injection point's value, so before
        // this control the line carried the same bytes DIFFERENCE 1 had already stripped one line up.
        assertTrue(
            detailFieldOf(offBlob).contains("$PAYLOAD_USED_PREFIX${PAYLOAD.value}") &&
                strictDetail.contains("$PAYLOAD_USED_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}") &&
                !strictDetail.contains(PAYLOAD.value),
            "DIFFERENCE 3 — 28-04'S CONTROL ON THE PAYLOAD LINE, inside `detail` — did not occur as " +
                "specified. The rendered payload '${PAYLOAD.value}' must be present on the OFF " +
                "'$PAYLOAD_USED_PREFIX' line and replaced WHOLESALE by " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' in the STRICT `detail`, " +
                "with no residue of the payload anywhere in that field. `sanitizeRenderedPayload` " +
                "is the side that moved.",
        )

        val predicted =
            withDetailLineControlsApplied(offBlob)
                .replace(POSITIVE_CONTROL_HEADER_BEFORE, POSITIVE_CONTROL_HEADER_AFTER)

        assertEquals(predicted, strictBlob, unenumeratedDifferenceMessage(predicted, strictBlob))
    }

    /**
     * (PRIV-05) 28-04 / `CR-01` — THE DESIGNATED RED PROBE FOR THE PAYLOAD CONTROL.
     *
     * This is the assertion 28-04's SC3 mutations are measured against. `28-VERIFICATION.md`
     * measured SC1 FALSE at this exact line: `ScannerIssueSupport.kt:121` rendered
     * `payload.value` with no policy argument, and for a COOKIE point production DERIVES that
     * payload from the cookie value, so the line re-leaked the bytes line 120 had just stripped.
     */
    @Test
    fun cookiePayloadIsStrippedUnderStrict() {
        val detail = detailFieldOf(redactedBlobFor(cookiePoint(), PrivacyMode.STRICT))

        assertFalse(
            detail.contains(DETAIL_SENTINEL),
            "STRICT / PAYLOAD LINE: the COOKIE-typed injection point's originalValue must be ABSENT " +
                "from the `detail` field, but the sentinel '$DETAIL_SENTINEL' was present. For a " +
                "COOKIE point the payload is DERIVED FROM that value, so an uncontrolled " +
                "'$PAYLOAD_USED_PREFIX' line re-leaks exactly what the 'Original Value: ' line just " +
                "stripped. Extracted detail: '$detail'",
        )
        assertFalse(
            detail.contains(PAYLOAD.value),
            "STRICT / PAYLOAD LINE: the rendered payload '${PAYLOAD.value}' must be ABSENT from the " +
                "`detail` field. Its presence means the payload survived the control verbatim.",
        )
        assertTrue(
            detail.contains("$PAYLOAD_USED_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "STRICT / PAYLOAD LINE: the '$PAYLOAD_USED_PREFIX' line must render the SHARED stripped " +
                "marker '${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' — the same " +
                "vocabulary the Original Value line uses — but it did not. Extracted detail: " +
                "'$detail'",
        )
    }

    @Test
    fun cookiePayloadIsStrippedUnderBalanced() {
        val detail = detailFieldOf(redactedBlobFor(cookiePoint(), PrivacyMode.BALANCED))

        assertFalse(
            detail.contains(DETAIL_SENTINEL),
            "BALANCED: the COOKIE-typed injection point's originalValue must be ABSENT from the " +
                "`detail` field, but the sentinel '$DETAIL_SENTINEL' was present on the " +
                "'$PAYLOAD_USED_PREFIX' line. BALANCED sets stripCookies just as STRICT does; a " +
                "control that fires only under STRICT reads the wrong half of the policy. " +
                "Extracted detail: '$detail'",
        )
        assertFalse(
            detail.contains(PAYLOAD.value),
            "BALANCED: the rendered payload '${PAYLOAD.value}' must be ABSENT from the `detail` field.",
        )
        assertTrue(
            detail.contains("$PAYLOAD_USED_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "BALANCED: the '$PAYLOAD_USED_PREFIX' line must render the stripped marker " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}', but it did not. " +
                "Extracted detail: '$detail'",
        )
    }

    /**
     * SC2 for route 1. The opposite mistake to the one above: a control that fires unconditionally
     * would be invisible to every absence assertion in this class while destroying the diagnostic
     * in the ONE mode the operator chose to keep it in.
     */
    @Test
    fun cookiePayloadSurvivesUnderOff() {
        val detail = detailFieldOf(redactedBlobFor(cookiePoint(), PrivacyMode.OFF))

        assertTrue(
            detail.contains("$PAYLOAD_USED_PREFIX${PAYLOAD.value}"),
            "OFF: the '$PAYLOAD_USED_PREFIX' line must carry the rendered payload " +
                "'${PAYLOAD.value}' VERBATIM — the control is policy-driven, not an unconditional " +
                "rewrite. Extracted detail: '$detail'",
        )
        assertTrue(
            detail.contains(DETAIL_SENTINEL),
            "OFF: the payload carries the sentinel '$DETAIL_SENTINEL' by construction, so the OFF " +
                "`detail` must contain it. Its absence means either the fixture stopped " +
                "interpolating or some rule other than this control removed it.",
        )
        assertFalse(
            detail.contains("$PAYLOAD_USED_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "OFF: the stripped marker must NOT appear on the '$PAYLOAD_USED_PREFIX' line; its " +
                "presence would mean a control fired in the mode defined as applying none.",
        )
    }

    /**
     * The payload line's attribution control, twinning
     * [urlParamOriginalValueSurvivesStrict_attributionControl]. Same value, same payload, different
     * TYPE — so a green cookie result above is attributable to the type gate and not to some
     * unrelated rule that happens to eat the sentinel or the payload text.
     */
    @Test
    @Suppress("ktlint:standard:function-naming")
    fun urlParamPayloadSurvivesStrict_attributionControl() {
        val detail = detailFieldOf(redactedBlobFor(urlParamPoint(), PrivacyMode.STRICT))

        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL"),
            "STRICT / ATTRIBUTION: a URL_PARAM-typed point carrying the IDENTICAL sentinel must " +
                "keep its 'Original Value: ' line verbatim. It did not, so the COOKIE assertions " +
                "are not attributable to the type gate. Extracted detail: '$detail'",
        )
        assertTrue(
            detail.contains("$PAYLOAD_USED_PREFIX${PAYLOAD.value}"),
            "STRICT / ATTRIBUTION: a URL_PARAM-typed point must keep its '$PAYLOAD_USED_PREFIX' " +
                "line verbatim, including '${PAYLOAD.value}'. Its absence would mean the payload " +
                "control is NOT type-keyed — it fires for every type, which reopens D-28-01's " +
                "deliberate pass-through. Extracted detail: '$detail'",
        )
    }

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

        /** The cookie NAME carrying [POSITIVE_CONTROL_COOKIE_VALUE] inside [RAW_REQUEST]. */
        const val POSITIVE_CONTROL_COOKIE_NAME = "wibble"

        /**
         * The marker the PRE-EXISTING header rule writes over a stripped `Cookie:` header.
         *
         * Deliberately NOT read from `ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER`. The two
         * are independently owned — one belongs to this plan's control inside `detail`, the other to
         * a rule that predates this phase — and they only HAPPEN to share the literal today. Reading
         * one from the other would make a future divergence in either of them invisible here, and
         * this file's whole-blob difference enumeration depends on telling the two apart.
         */
        const val HEADER_RULE_STRIPPED_MARKER = "[STRIPPED]"

        /** The positive control's header line as WRITTEN, before any rule fires. */
        const val POSITIVE_CONTROL_HEADER_BEFORE =
            "Cookie: $POSITIVE_CONTROL_COOKIE_NAME=$POSITIVE_CONTROL_COOKIE_VALUE"

        /** The positive control's header line as the PRE-EXISTING header rule rewrites it. */
        const val POSITIVE_CONTROL_HEADER_AFTER = "Cookie: $HEADER_RULE_STRIPPED_MARKER"

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

        /** Half-width of the context window printed either side of a divergence in a failure message. */
        const val DIFF_WINDOW_CHARS = 60

        val METADATA_SECTION = "$METADATA_SECTION_MARKER\r\nScan: Active\r\nConfidence: 90"

        const val HOST_SALT = "phase-28-fixed-salt"

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

        val RAW_REQUEST =
            "GET /basket HTTP/1.1\r\n" +
                "Host: shop.example\r\n" +
                "$POSITIVE_CONTROL_HEADER_BEFORE\r\n" +
                "Accept: text/html\r\n\r\n"

        fun cookiePoint() = InjectionPoint(InjectionType.COOKIE, COOKIE_POINT_NAME, DETAIL_SENTINEL)

        fun urlParamPoint() = InjectionPoint(InjectionType.URL_PARAM, COOKIE_POINT_NAME, DETAIL_SENTINEL)

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

        fun issueDetailsFor(
            point: InjectionPoint,
            mode: PrivacyMode,
        ): IssueDetails {
            val lines = detailLinesFor(point, mode)
            return IssueDetails(
                name = "[AI Active] ${VulnClass.SQLI.name}",
                detail = IssueUtils.formatIssueDetailHtml(lines),
                remediation = "remediation",
                httpService = HttpService(host = "shop.example", port = 443, secure = true),
                baseUrl = "https://shop.example/basket",
                severity = AuditIssueSeverity.HIGH,
                confidence = AuditIssueConfidence.FIRM,
                requestResponses =
                    listOf(
                        HttpRequestResponse(
                            request = RAW_REQUEST,
                            response = "HTTP/1.1 200 OK\r\n\r\n",
                            notes = null,
                        ),
                    ),
                collaboratorInteractions = emptyList(),
                definition =
                    AuditIssueDefinition(
                        id = "ai_active_confirmed",
                        background = "background",
                        remediation = "remediation",
                        typeIndex = 1,
                    ),
            )
        }

        fun redactedBlobFor(
            point: InjectionPoint,
            mode: PrivacyMode,
        ): String =
            Redaction.apply(
                toolJson.encodeToString(issueDetailsFor(point, mode)),
                RedactionPolicy.fromMode(mode),
                HOST_SALT,
            )

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

        /**
         * Extracts the `detail` FIELD from a redacted blob.
         *
         * FIELD-SCOPED ON PURPOSE, and the whole reason the content-destruction guard can exist at
         * all: a WHOLE-BLOB form of that guard is false by construction on this fixture, because the
         * positive-control `Cookie:` header inside `requestResponses` is legitimately stripped by a
         * pre-existing rule in the same STRICT output and sits AFTER the sentinel in the same
         * serialized string.
         */
        fun detailFieldOf(blob: String): String {
            val viaParse = runCatching { parsedOrNull(blob)?.get("detail")?.jsonPrimitive?.content }.getOrNull()
            return viaParse ?: fallbackStringField(blob, "detail")
        }

        /** Extracts `requestResponses[0].request` from a redacted blob. */
        fun requestFieldOf(blob: String): String {
            val viaParse =
                runCatching {
                    parsedOrNull(blob)
                        ?.get("requestResponses")
                        ?.jsonArray
                        ?.get(0)
                        ?.jsonObject
                        ?.get("request")
                        ?.jsonPrimitive
                        ?.content
                }.getOrNull()
            return viaParse ?: fallbackStringField(blob, "request")
        }

        fun parsedOrNull(blob: String): JsonObject? = runCatching { Json.parseToJsonElement(blob).jsonObject }.getOrNull()

        /**
         * Substring fallback for the case where a redaction rule produced output that no longer
         * parses as JSON. A guard that silently vanished in that case would be worse than one that
         * degrades: this returns the field's ESCAPED text rather than its decoded value, which is
         * consistent for every caller because the fallback either fires for all of them or none.
         */
        fun fallbackStringField(
            blob: String,
            key: String,
        ): String {
            val marker = "\"$key\":\""
            val start = blob.indexOf(marker)
            assertTrue(
                start >= 0,
                "EXTRACTOR: neither a JSON parse nor a substring scan located the `$key` field in " +
                    "the redacted blob. Every guard downstream of this call measures nothing.",
            )
            val valueStart = start + marker.length
            var index = valueStart
            while (index < blob.length) {
                if (blob[index] == '"' && trailingBackslashCount(blob, index) % 2 == 0) {
                    return blob.substring(valueStart, index)
                }
                index++
            }
            assertTrue(
                false,
                "EXTRACTOR: the `$key` field's opening quote was found but its closing quote was " +
                    "not. The redacted blob is truncated or malformed.",
            )
            return ""
        }

        fun trailingBackslashCount(
            text: String,
            index: Int,
        ): Int {
            var count = 0
            var cursor = index - 1
            while (cursor >= 0 && text[cursor] == '\\') {
                count++
                cursor--
            }
            return count
        }

        /**
         * (PRIV-05) 28-04 — predicts the STRICT rendering of [text] by applying THIS FILE'S TWO
         * detail-line controls to it, and nothing else. [text] may be an extracted `detail` field or
         * a whole serialized blob: both substitutions are keyed on rendered LINE PREFIXES, which
         * survive JSON encoding unescaped.
         *
         * BOTH SUBSTITUTIONS ARE PREFIX-QUALIFIED, and that property is what makes the prediction
         * falsifiable. Before 28-04 this prediction was a single UNQUALIFIED
         * `replace(DETAIL_SENTINEL, marker)`, written when exactly one sentinel occurrence lived
         * inside `detail`. The rendered payload now CONTAINS the sentinel by construction —
         * production derives a COOKIE point's payload by interpolating its value — so an unqualified
         * replace rewrites the sentinel INSIDE the payload text too, and predicts a payload line
         * reading marker-plus-suffix where the shipped control writes the marker ALONE.
         *
         * [edge:ordering] THE PAYLOAD SUBSTITUTION IS WRITTEN FIRST, and this states WHY rather than
         * merely THAT. It is the substitution whose key an unqualified sentinel rewrite would
         * destroy — its key contains the sentinel, the other's does not — so it runs before anything
         * else can touch the text. The MEASURED result of both orderings is recorded in
         * `28-04-SUMMARY.md`, including the finding that with both substitutions prefix-qualified a
         * bare order swap is a NO-OP: prefix-qualification, not order alone, is what carries the
         * safety here, and the order is kept fixed so that a future edit which drops a
         * qualification cannot silently reintroduce the hazard.
         *
         * WHY NOT KEEP THE GLOBAL SENTINEL REPLACE, which would be shorter. A global replace ABSORBS
         * a sentinel occurrence appearing ANYWHERE ELSE in the blob — it would silently swallow a
         * THIRD uncontrolled route carrying the same bytes, which is exactly the class of miss this
         * gap round exists to correct. Prefix-qualified substitutions leave such an occurrence
         * standing as an unexplained residue and the equality turns red on it.
         */
        fun withDetailLineControlsApplied(text: String): String =
            text
                .replace(
                    "$PAYLOAD_USED_PREFIX${payloadRenderedFor(cookiePoint(), PrivacyMode.OFF)}",
                    "$PAYLOAD_USED_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}",
                ).replace(
                    "$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL",
                    "$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}",
                )

        fun windowAround(
            text: String,
            index: Int,
        ): String {
            val start = maxOf(0, index - DIFF_WINDOW_CHARS)
            val end = minOf(text.length, index + DIFF_WINDOW_CHARS)
            return if (start >= end) "<empty>" else text.substring(start, end)
        }

        fun contentDestructionMessage(
            expected: String,
            actual: String,
        ): String {
            val divergence = expected.commonPrefixWith(actual).length
            return "CONTENT DESTRUCTION, FIELD-SCOPED to `detail`: the STRICT `detail` must equal " +
                "the OFF `detail` under EXACTLY TWO PREFIX-QUALIFIED substitutions — the " +
                "'$PAYLOAD_USED_PREFIX' line's rendered payload became " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}', and so did the " +
                "'$ORIGINAL_VALUE_PREFIX' line's sentinel — and under no other. They first diverge " +
                "at index $divergence.\n" +
                "  expected: ...${windowAround(expected, divergence)}...\n" +
                "  actual:   ...${windowAround(actual, divergence)}...\n" +
                "The divergence is EITHER a real over-match that ate content past a control's span, " +
                "OR a second redaction rule firing on a fixture token, OR a THIRD detail line that " +
                "acquired a control without being enumerated here. Diagnose WHICH and record it in " +
                "the round's SUMMARY. Relaxing this assertion is not one of those options: relaxing " +
                "a guard that was red on arrival is exactly how phase 27 round 4 shipped a " +
                "content-destruction regression."
        }

        fun unenumeratedDifferenceMessage(
            predicted: String,
            observed: String,
        ): String {
            val divergence = predicted.commonPrefixWith(observed).length
            return "AN UNENUMERATED DIFFERENCE between the OFF and STRICT blobs was found. " +
                "Applying the three KNOWN substitutions to the OFF blob — the " +
                "'$ORIGINAL_VALUE_PREFIX' line's sentinel becomes " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}' inside `detail`, the " +
                "'$PAYLOAD_USED_PREFIX' line's rendered payload becomes the same marker inside " +
                "`detail`, and '$POSITIVE_CONTROL_HEADER_BEFORE' becomes " +
                "'$POSITIVE_CONTROL_HEADER_AFTER' inside requestResponses — must reproduce the " +
                "STRICT blob EXACTLY. A residue remains, first differing at index $divergence.\n" +
                "  predicted: ...${windowAround(predicted, divergence)}...\n" +
                "  observed:  ...${windowAround(observed, divergence)}...\n" +
                "An unenumerated difference in this blob is either an over-match or a rule nobody " +
                "accounted for. Both are FINDINGS, not fixture noise. Diagnose which, and do not " +
                "widen the substitution list to absorb it."
        }
    }
}
