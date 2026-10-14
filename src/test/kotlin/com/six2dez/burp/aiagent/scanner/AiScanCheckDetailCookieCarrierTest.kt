package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * (PRIV-05) Phase 28 plan 28-05 — `AR-27-08` ROUTE 2 (`CR-02`), the SECOND issue-detail cookie
 * carrier.
 *
 * WHAT THIS FILE IS. `AiScanCheck.buildDetail` is a second producer of active-scan
 * `AuditIssue.detail()` text, live-registered `PER_INSERTION_POINT` at `App.kt:214-215`, whose
 * output reaches the `scanner_issues` MCP tool result through `api.siteMap()`. Before plan 28-05 it
 * read NO privacy mode at all: `grep -n 'Redaction|PrivacyMode|RedactionPolicy|sanitize|privacyMode'`
 * over the file returned nothing, so it rendered a `PARAM_COOKIE` insertion point's `baseValue()`
 * identically under STRICT, BALANCED and OFF. This file measures the control that closes that.
 *
 * THIS IS THE FIRST TEST IN THIS REPOSITORY TO FAKE A MONTOYA `AuditInsertionPoint`. Measured at the
 * commit this file was written against: `grep -rl 'AuditInsertionPoint' src/test/kotlin/` listed
 * ZERO files. There was therefore no analog to copy, and the shape below is new rather than
 * borrowed.
 *
 * WHY THE OBVIOUS END-TO-END SHAPE IS UNAVAILABLE, stated so nobody "fixes" this file by rewriting
 * it as a `doCheck` test. `AuditIssue.auditIssue(...)` and `AuditResult.auditResult(...)` both route
 * through Burp's `ObjectFactoryLocator.FACTORY`, which is NULL outside the Burp runtime.
 * `AiPassiveScanCheckTest` — the only other test that drives a Burp `ScanCheck` — works around that
 * by CATCHING the resulting `NullPointerException` rather than by faking the factory. So this file
 * cannot reach `buildDetail` through the issue-construction path; it calls `buildDetail` directly,
 * which is why plan 28-05 widened that function from `private` to `internal`.
 *
 * PHASE 29: serialized-tail assertions now live in FullAiScanCheckDetailCookieCarrierTest.
 * This core half retains scanner-side assertions and fixtures. The original route description
 * below describes the two classes together.
 *
 * WHAT THIS FILE THEREFORE PROVES, and what it does NOT.
 *
 * PROVES: for the string `buildDetail` actually returns, a `PARAM_COOKIE` point's `baseValue()` is
 * absent under STRICT and BALANCED and present under OFF, measured through the REAL serialization
 * tail — `IssueDetails` -> `toolJson.encodeToString` -> `Redaction.apply` -> the extracted `detail`
 * field — with the pre-existing `Cookie:` header rule firing in the SAME output as a positive
 * control. Measuring through `Redaction.apply` is the point: `28-VERIFICATION.md` `missing[6]`
 * recorded that this shape had never been passed through the redactor, and an assertion on a bare
 * string would not have discharged it.
 *
 * DOES NOT PROVE: that the operator's configured privacy mode reaches `buildDetail` in production.
 * That link is the `getSettings()` call on `buildDetail`'s first line and the `App.kt:214-215`
 * wiring; no assertion here executes either. This is the same residual `IssueDetailCookieCarrierTest`
 * names for route 1, and it is stated rather than papered over.
 *
 * SENTINEL ISOLATION. Every sentinel here is DISTINCT from `IssueDetailCookieCarrierTest`'s. If the
 * two files shared one, a cross-class collision could make an absence assertion pass for entirely
 * the wrong reason, and the two files run in the same JVM.
 */
class AiScanCheckDetailCookieCarrierTest {
    @BeforeEach
    fun clearCustomPatterns() {
        // Redaction is a singleton object: custom patterns left behind by another test class in the
        // same JVM would bleed in here and could remove a sentinel for the wrong reason, letting an
        // absence assertion pass without this plan's control doing anything. Precedent:
        // IssueDetailCookieCarrierTest's own @BeforeEach.
        Redaction.setCustomPatterns(emptyList())
    }

    /**
     * THE FIXTURE PIN, and it runs before any behavioural assertion is read as evidence.
     *
     * A mock whose `type()` stub silently did not take would return null, [isCookieInsertionPoint]
     * would return false, the control would never fire — and EVERY absence assertion below would
     * still pass, because a mock that also failed to stub `baseValue()` renders no sentinel either.
     * That is the class of vacuity `IssueDetailCookieCarrierTest`'s extractor pins exist to prevent,
     * reproduced here for the collaborator this file fakes.
     */
    @Test
    fun theInsertionPointMockActuallyReturnsWhatItWasStubbedToReturn() {
        val point = cookieInsertionPoint()

        assertEquals(
            AuditInsertionPointType.PARAM_COOKIE,
            point.type(),
            "FIXTURE: the AuditInsertionPoint mock must return PARAM_COOKIE from type(). It returned " +
                "'${point.type()}'. If the stub did not take, the gate never fires and every " +
                "absence assertion in this file passes while measuring nothing.",
        )
        assertEquals(
            DETAIL_SENTINEL,
            point.baseValue(),
            "FIXTURE: the AuditInsertionPoint mock must return the sentinel '$DETAIL_SENTINEL' from " +
                "baseValue(). It returned '${point.baseValue()}'. A mock that renders no value at " +
                "all would make every absence assertion below vacuous.",
        )
    }

    // =============================================================================================
    // ROUTE 2'S `Payload Used:` LINE - WHAT A GREEN RUN BELOW DOES AND DOES NOT MEAN.
    //
    // Read this before the first assertion. `ISSUE_DETAIL_CARRIER_DISPOSITION` and `26-SECURITY.md`
    // row 315 both name THIS CLASS as the committed probe for detail line (4). Until plan 28-07 that
    // claim was unsupported: `grep -o "Payload Used"` on this file returned ZERO, KDoc included. The
    // four tests below make that claim TRUE of the file. They do NOT convert this line into a closed
    // leak, and no artifact may cite them as one.
    //
    // THE ASYMMETRY, in `AiScanCheck.buildDetail`'s own terms rather than a paraphrase of them. The
    // `Original Value:` line IS a measured carrier: `baseValue()` on a `PARAM_COOKIE` insertion
    // point is the operator's raw cookie value, taken by Burp from proxied traffic. The
    // `Payload Used:` line is NOT a carrier at HEAD: this class sources payloads from
    // `payloadGenerator.getQuickPayloads(...)`, which returns entries from a STATIC table and
    // interpolates no value (`PayloadGenerator.kt:633-639`) - unlike `ActiveAiScanner`'s
    // context-aware route, which is what made route 1's payload line a real leak. It is controlled
    // here as DEFENCE IN DEPTH and for vocabulary parity with route 1, nothing more.
    //
    // THE PROOF IS IN THE FIXTURE, NOT IN THIS COMMENT. [PAYLOAD]'s value carries no trace of
    // [DETAIL_SENTINEL], which is why the companion's KDoc says that fixture is hand-built ON
    // PURPOSE while route 1's is DERIVED from `PayloadGenerator`. That absence is what makes the
    // paragraph above honest rather than decorative. Calling these assertions a leak closure would
    // be exactly the overclaim vocabulary the phase-27/28 series exists to correct.
    // =============================================================================================

    /** Line (4) under STRICT - the stripping arm. */
    @Test
    fun cookiePayloadLineIsStrippedUnderStrict() {
        val rendered = payloadLineRenderedFor(cookieInsertionPoint(), PrivacyMode.STRICT)

        assertEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            rendered,
            "STRICT: a PARAM_COOKIE point's 'Payload Used:' value must be the shared " +
                "marker '${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}'. It was " +
                "'$rendered'. The marker is REFERENCED from ScannerIssueSupport and never retyped " +
                "here - D-28-05's one-vocabulary rule makes a second marker literal in this file " +
                "the named failure mode.",
        )
    }

    /** Line (4) under the other stripping mode - `stripCookies` is policy-driven, not STRICT-keyed. */
    @Test
    fun cookiePayloadLineIsStrippedUnderBalanced() {
        val rendered = payloadLineRenderedFor(cookieInsertionPoint(), PrivacyMode.BALANCED)

        assertEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            rendered,
            "BALANCED: a PARAM_COOKIE point's 'Payload Used:' value must be the shared " +
                "marker '${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}'. It was " +
                "'$rendered'. RedactionPolicy.fromMode sets stripCookies = true for BALANCED as " +
                "well as STRICT, so a gate that only fires under STRICT is keyed on the MODE rather " +
                "than on the policy.",
        )
    }

    /**
     * THE NON-VACUITY ARM. Without it the two stripping assertions above could both pass on a
     * payload line that was absent or empty in every mode, proving nothing about the gate.
     */
    @Test
    fun cookiePayloadLineSurvivesUnderOff() {
        val rendered = payloadLineRenderedFor(cookieInsertionPoint(), PrivacyMode.OFF)

        assertEquals(
            PAYLOAD.value,
            rendered,
            "OFF: RedactionPolicy.fromMode(OFF) sets stripCookies = false, so the " +
                "'Payload Used:' value must be the fixture payload '${PAYLOAD.value}' VERBATIM. " +
                "It was '$rendered'. If it is not, the STRICT and BALANCED assertions above are " +
                "vacuous - they would pass on a line that never carried a value in any mode.",
        )
    }

    /**
     * ATTRIBUTION CONTROL for line (4). Mirrors
     * [urlParamInsertionPointSurvivesStrict_attributionControl], which does the same job for line
     * (2): the same value under the same mode, differing only in the point's TYPE.
     */
    @Test
    fun urlParamPayloadLineSurvivesStrict_attributionControl() {
        val rendered = payloadLineRenderedFor(urlParamInsertionPoint(), PrivacyMode.STRICT)

        assertEquals(
            PAYLOAD.value,
            rendered,
            "STRICT: a PARAM_URL point carrying the IDENTICAL payload must keep its " +
                "'Payload Used:' value verbatim as '${PAYLOAD.value}'. It was '$rendered'. The " +
                "gate is keyed on AuditInsertionPointType.PARAM_COOKIE; stripping here would mean " +
                "the payload-line gate is not type-keyed at all, and the two stripping assertions " +
                "above would prove nothing about the TYPE.",
        )
    }

    /**
     * [edge:empty] A `PARAM_COOKIE` point whose `baseValue()` is the EMPTY STRING still renders the
     * marker.
     *
     * The gate is keyed on the TYPE, never on the value being non-empty — the same choice
     * `ScannerIssueSupport.sanitizeRenderedPayload` records. An emptiness guard would let this point
     * through, and the point's TYPE would then become observable as a difference in the rendered
     * line.
     *
     * Asserted on the raw `buildDetail` output rather than through the redactor: there is no
     * sentinel to look for here, so a redaction pass would only stand between the assertion and the
     * thing it measures.
     */
    @Test
    fun anEmptyBaseValueStillRendersTheMarkerUnderStrict() {
        val detail = detailFor(emptyValuedCookieInsertionPoint(), PrivacyMode.STRICT)

        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "STRICT: an EMPTY-valued PARAM_COOKIE point must still render " +
                "'$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}'. " +
                "Rendering an empty value instead would make the point's TYPE observable as a " +
                "difference in the line, which is exactly what an emptiness guard costs. Detail " +
                "was: $detail",
        )
    }

    /**
     * [edge:empty] An insertion point whose `type()` is ABSENT does not throw — it takes the
     * pass-through branch.
     *
     * THE PREMISE, MEASURED RATHER THAN ASSUMED (corrected by plan 28-07). This KDoc previously
     * claimed that `type()` is a Java default method returning a platform type "and a real Burp
     * implementation may not override it", which reads as: a real implementation could hand back
     * null. That is FALSE against the shipped jar. `javap -c` on the resolved
     * `montoya-api-2026.2.jar` shows `AuditInsertionPoint.type()` is a DEFAULT method whose ENTIRE
     * body is `getstatic AuditInsertionPointType.EXTENSION_PROVIDED; areturn`, so an implementation
     * that does not override it returns `EXTENSION_PROVIDED` and never null. The reasoning is
     * replaced; the test and its assertion are not.
     *
     * WHAT THIS TEST THEREFORE PROVES, AND WHAT IT DOES NOT. The null arm is reachable through a
     * MOCK with `type()` left UNSTUBBED, which is exactly the fixture below. Pinning it is still
     * worth doing: an identity comparison handles null correctly BY CONSTRUCTION, and this test
     * holds that rather than leaving it to a reader's confidence about Kotlin's `==`. But it is NOT
     * the real-Burp arm. The arm a non-overriding real implementation actually takes is
     * `EXTENSION_PROVIDED`, and that one is covered by
     * [theRouteTwoGateIsFailOpenForTheseCookieCapableTypes] — where it is recorded as a named
     * fail-open RESIDUAL rather than as correct behaviour. Both arms reach the pass-through branch,
     * for different reasons, and neither is left implied.
     */
    @Test
    fun anAbsentInsertionPointTypeDoesNotThrowAndPassesThrough() {
        val detail = detailFor(untypedInsertionPoint(), PrivacyMode.STRICT)

        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL"),
            "STRICT: an insertion point with no type() must not throw and must take the " +
                "pass-through branch, keeping '$DETAIL_SENTINEL' verbatim. The gate has no " +
                "knowledge of what an untyped point is and must not guess it is a cookie. Detail " +
                "was: $detail",
        )
    }

    /**
     * [edge:encoding] WHOSE DEFINITION OF TYPE EQUALITY APPLIES — measured, not re-derived by
     * inspection.
     *
     * This is the single highest-risk item of plan 28-05 and the reason route 2 needed its OWN
     * predicate. `Redaction.isCookieParameterType` compares a trimmed, upper-cased parameter-type
     * NAME against the literal `COOKIE`. The Montoya INSERTION-POINT constant's name is
     * `PARAM_COOKIE`. The shared predicate therefore returns FALSE for it, and a plan that had
     * reused the shared predicate here would have shipped a control that compiles, reads as correct
     * and never fires.
     *
     * Pinning it as an assertion means a future reader cannot re-derive it wrongly from the two
     * files' prose.
     */
    @Test
    fun theSharedStringNamePredicateDoesNotRecogniseTheInsertionPointCookieConstant() {
        val insertionPointConstantName = AuditInsertionPointType.PARAM_COOKIE.name

        assertEquals(
            "PARAM_COOKIE",
            insertionPointConstantName,
            "the Montoya insertion-point cookie constant is expected to be named PARAM_COOKIE. It " +
                "is named '$insertionPointConstantName'. If Burp renamed it, the measurement below " +
                "and AiScanCheck.isCookieInsertionPoint's KDoc both need re-deriving.",
        )
        assertFalse(
            Redaction.isCookieParameterType(insertionPointConstantName),
            "MEASURED: Redaction.isCookieParameterType('$insertionPointConstantName') must be " +
                "FALSE. It compares a trimmed, upper-cased PARAMETER-type name against the literal " +
                "COOKIE, and the INSERTION-POINT constant is named PARAM_COOKIE. This is WHY route " +
                "2 keys on an enum identity compare against " +
                "AuditInsertionPointType.PARAM_COOKIE instead of reusing the shared predicate. If " +
                "this assertion ever goes green, the shared predicate has been widened and the two " +
                "cookie-type populations CookieRouteDispositionTest keeps apart have merged — read " +
                "that file's class KDoc before changing anything here.",
        )
    }

    /**
     * THE ROUTE-2 FAIL-OPEN SET, NAMED (`D-28-11`, plan 28-07).
     *
     * READ THIS BEFORE READING THE ASSERTIONS. A GREEN run here is NOT evidence of correct
     * behaviour. It records the exact WIDTH of a residual plan 28-07 chose to NAME rather than
     * close, and the four reasons for that choice are written at
     * `AiScanCheck.isCookieInsertionPoint`'s KDoc rather than restated here.
     *
     * Four members of `AuditInsertionPointType` can carry a cookie value while not being
     * `PARAM_COOKIE` — `HEADER` (a `Cookie:` request header presented as a header insertion point),
     * `USER_PROVIDED`, `EXTENSION_PROVIDED` and `UNKNOWN` — and the gate passes all four through.
     * `EXTENSION_PROVIDED` is the most consequential of the four: it is what `type()`'s default body
     * returns, so it is the arm a real Burp implementation that does not override `type()` takes.
     */
    @Test
    fun theRouteTwoGateIsFailOpenForTheseCookieCapableTypes() {
        val cookieCapableNonCookieTypes =
            listOf(
                AuditInsertionPointType.HEADER,
                AuditInsertionPointType.USER_PROVIDED,
                AuditInsertionPointType.EXTENSION_PROVIDED,
                AuditInsertionPointType.UNKNOWN,
            )

        cookieCapableNonCookieTypes.forEach { type ->
            val point = insertionPoint(type, DETAIL_SENTINEL)

            assertFalse(
                AiScanCheck.isCookieInsertionPoint(point),
                "RESIDUAL, NOT A CONTROL: AiScanCheck.isCookieInsertionPoint returns FALSE for " +
                    "AuditInsertionPointType.$type, because the gate is an identity compare against " +
                    "PARAM_COOKIE alone. This member CAN carry a cookie value, so the gate is " +
                    "fail-OPEN for it and this assertion records that width. If it goes RED the " +
                    "predicate was WIDENED — read AiScanCheck.isCookieInsertionPoint's KDoc and " +
                    "D-28-11 before accepting that, and re-state the residual at every record site.",
            )

            val detail = detailFor(point, PrivacyMode.STRICT)

            assertTrue(
                detail.contains("$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL"),
                "RESIDUAL, NOT A CONTROL: under STRICT an AuditInsertionPointType.$type point's " +
                    "baseValue() still reaches the detail line VERBATIM as " +
                    "'$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL'. That is the residual's OBSERVABLE " +
                    "width, recorded here so no reader has to infer it from the predicate. Detail " +
                    "was: $detail",
            )
        }
    }

    /**
     * THE TRIPWIRE THAT BOUNDS THE RESIDUAL.
     *
     * The test above enumerates FOUR cookie-capable non-`PARAM_COOKIE` members. That number is only
     * meaningful against a KNOWN population: if a Burp API bump adds a member, the residual widens
     * and every record naming it silently becomes an understatement. Pinning the population is what
     * turns that silence into a red test, and it is the same discipline 28-PATTERNS' "type-keyed,
     * never shape-keyed" note applies to the constant itself — state a measured property as an
     * assertion, never as prose a reader must trust.
     */
    @Test
    fun theInsertionPointTypeEnumPopulationIsTheOneTheResidualWasMeasuredAgainst() {
        val observedNames = AuditInsertionPointType.values().map { it.name }.toSet()

        assertEquals(
            MEASURED_INSERTION_POINT_TYPE_COUNT,
            AuditInsertionPointType.values().size,
            "AuditInsertionPointType was measured at $MEASURED_INSERTION_POINT_TYPE_COUNT members " +
                "in montoya-api-2026.2 when the route-2 fail-open residual was written down; it now " +
                "has ${AuditInsertionPointType.values().size}. WHAT TO DO: Burp added or removed a " +
                "member, so re-derive which members are cookie-capable, then re-state the residual " +
                "at AiScanCheck.isCookieInsertionPoint's KDoc, in ISSUE_DETAIL_CARRIER_DISPOSITION " +
                "and in 26-SECURITY.md row 315 before updating this list.",
        )
        assertEquals(
            MEASURED_INSERTION_POINT_TYPE_NAMES,
            observedNames,
            "the AuditInsertionPointType member NAMES must be the set the residual was measured " +
                "against. Observed: $observedNames. A rename is as consequential as an addition: " +
                "theRouteTwoGateIsFailOpenForTheseCookieCapableTypes names four members literally, " +
                "and a renamed member would either stop compiling or quietly stop being covered.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture and the serialization tail.
    //
    // The tail below — IssueDetails -> toolJson.encodeToString -> Redaction.apply -> extract the
    // `detail` field — is borrowed in SHAPE from IssueDetailCookieCarrierTest, which is the only
    // existing way to measure an issue-detail string through the redactor. The extractors are
    // duplicated rather than shared because that file's are private companion members; keeping them
    // private there and copied here is the smaller cost, and the copies carry the same fail-loud
    // behaviour.
    // ---------------------------------------------------------------------------------------------

    private fun cookieInsertionPoint(): AuditInsertionPoint = insertionPoint(AuditInsertionPointType.PARAM_COOKIE, DETAIL_SENTINEL)

    private fun urlParamInsertionPoint(): AuditInsertionPoint = insertionPoint(AuditInsertionPointType.PARAM_URL, DETAIL_SENTINEL)

    private fun emptyValuedCookieInsertionPoint(): AuditInsertionPoint = insertionPoint(AuditInsertionPointType.PARAM_COOKIE, "")

    /**
     * An insertion point with NO type at all.
     *
     * `type()` is deliberately left UNSTUBBED rather than stubbed to null: Mockito's default answer
     * for an unstubbed object-returning method — including a Java default method — is already null,
     * and stubbing it explicitly would only add a way for the stub to be the thing under test.
     */
    private fun untypedInsertionPoint(): AuditInsertionPoint {
        val point = mock<AuditInsertionPoint>()
        whenever(point.name()).thenReturn(INSERTION_POINT_NAME)
        whenever(point.baseValue()).thenReturn(DETAIL_SENTINEL)
        return point
    }

    private fun insertionPoint(
        type: AuditInsertionPointType,
        baseValue: String,
    ): AuditInsertionPoint {
        val point = mock<AuditInsertionPoint>()
        whenever(point.name()).thenReturn(INSERTION_POINT_NAME)
        whenever(point.baseValue()).thenReturn(baseValue)
        whenever(point.type()).thenReturn(type)
        return point
    }

    /**
     * Settings carrying the mode under test.
     *
     * `AgentSettingsRepository.defaultSettings()` is used rather than a hand-built [AgentSettings]
     * so a new settings field cannot leave this fixture silently stale, and it is driven off a
     * deep-stubbed `MontoyaApi` because the repository's constructor only needs
     * `api.persistence().preferences()`; `defaultSettings()` reads no preference at all.
     */
    private fun settingsFor(mode: PrivacyMode): AgentSettings =
        AgentSettingsRepository(mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
            .defaultSettings()
            .copy(privacyMode = mode, preferredBackendId = BACKEND_ID)

    /** The raw string `buildDetail` returns, before any redaction pass. */
    private fun detailFor(
        point: AuditInsertionPoint,
        mode: PrivacyMode,
    ): String = AiScanCheck(mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)) { settingsFor(mode) }.buildDetail(point, PAYLOAD, EVIDENCE)

    /**
     * The value route 2 renders in the single `<br>`-joined, HTML-escaped segment that starts with
     * [PAYLOAD_USED_PREFIX] (Phase 32 D-10 moved route 2 to route 1's escaped `<br>` shape).
     *
     * Shaped after route 1's `originalValueRenderedFor`, INCLUDING its single-producer assertion -
     * and therefore including the limitation D-28-06 named for it, stated here so a copy of the
     * shape cannot be read as a copy of a guarantee it never had: this filters the string THIS
     * producer itself returned, and is structurally unable to see a second producer in another file.
     * It is NOT the repository-wide detail-producer gate `WR-01` describes, that gate remains a
     * NAMED RESIDUAL, and no artifact may cite this assertion as one.
     *
     * The fixture values ([PAYLOAD], [DETAIL_SENTINEL], the shared marker) contain no `&`, `<` or
     * `>`, so the escaping leaves them byte-identical and the text after the prefix IS the value.
     */
    private fun payloadLineRenderedFor(
        point: AuditInsertionPoint,
        mode: PrivacyMode,
    ): String {
        val segments = detailFor(point, mode).split(LINE_BREAK)
        val prefixIndices = segments.indices.filter { segments[it].startsWith(PAYLOAD_USED_PREFIX) }

        assertEquals(
            1,
            prefixIndices.size,
            "SINGLE PRODUCER: exactly one detail segment may carry the '$PAYLOAD_USED_PREFIX' prefix. " +
                "Found ${prefixIndices.size} at indices $prefixIndices. A second producer is how a " +
                "control like this gets bypassed without anyone editing it. Detail was: $segments",
        )

        return segments[prefixIndices[0]].removePrefix(PAYLOAD_USED_PREFIX)
    }

    private companion object {
        /**
         * The value carried by the insertion point and written into the detail blob by
         * `Original Value:`.
         *
         * Low-entropy hyphenated words: no digits, no `=`, no metacharacters, so only the new type
         * gate can plausibly remove it. Deliberately does NOT contain the token `cookie`, so no
         * header-name rule can bind to it. DISTINCT from every sentinel in
         * `IssueDetailCookieCarrierTest` — the two classes run in the same JVM and a shared sentinel
         * would let a cross-class collision satisfy an absence assertion for the wrong reason.
         */
        const val DETAIL_SENTINEL = "cedar-anchor-marble-feather"

        /**
         * The POSITIVE CONTROL: the value of a real `Cookie:` header inside the same object's
         * `requestResponses`, guarded by a rule that predates this phase. Unrelated to
         * [DETAIL_SENTINEL] by construction.
         */
        const val POSITIVE_CONTROL_COOKIE_VALUE = "walnut-ribbon-quarry-saddle"

        /** The insertion point's NAME. Names survive every mode; values do not. */
        const val INSERTION_POINT_NAME = "juniper-satchel-name"

        /** The cookie NAME carrying [POSITIVE_CONTROL_COOKIE_VALUE] inside [RAW_REQUEST]. */
        const val POSITIVE_CONTROL_COOKIE_NAME = "wobble"

        /** The positive control's header line as WRITTEN, before any rule fires. */
        const val POSITIVE_CONTROL_HEADER_BEFORE = "Cookie: $POSITIVE_CONTROL_COOKIE_NAME=$POSITIVE_CONTROL_COOKIE_VALUE"

        /** The rendered prefix of the detail segment this plan's control owns, as route 2 spells it. */
        const val ORIGINAL_VALUE_PREFIX = "Original Value: "

        /**
         * The rendered prefix of route 2's SECOND controlled detail segment, as `buildDetail` spells
         * it. Since Phase 32 D-10 the prefix and the sanitized, escaped value share ONE
         * `<br>`-separated segment, the same shape route 1 renders.
         */
        const val PAYLOAD_USED_PREFIX = "Payload Used: "

        /** The separator `IssueUtils.formatIssueDetailHtml` joins the detail's lines with. */
        const val LINE_BREAK = "<br>"

        /**
         * The last line `AiScanCheck.buildDetail` writes, used as the non-vacuity tail marker. No
         * digits, no dots: nothing another redaction rule can plausibly claim, so its presence in
         * the tail measures the FIXTURE's shape rather than some rule's behaviour.
         */
        const val TAIL_MARKER = "Confirmed via active exploitation testing"

        /**
         * The `AuditInsertionPointType` population the route-2 fail-open residual was measured
         * against, from `javap` on the resolved `montoya-api-2026.2.jar`. Held as a constant rather
         * than a magic number so the two assertions in
         * [theInsertionPointTypeEnumPopulationIsTheOneTheResidualWasMeasuredAgainst] cannot drift
         * apart from each other.
         */
        const val MEASURED_INSERTION_POINT_TYPE_COUNT = 17

        /** The 17 member names, in the order `javap` lists them. */
        val MEASURED_INSERTION_POINT_TYPE_NAMES =
            setOf(
                "PARAM_URL",
                "PARAM_BODY",
                "PARAM_COOKIE",
                "PARAM_XML",
                "PARAM_XML_ATTR",
                "PARAM_MULTIPART_ATTR",
                "PARAM_JSON",
                "PARAM_AMF",
                "HEADER",
                "PARAM_NAME_URL",
                "PARAM_NAME_BODY",
                "ENTIRE_BODY",
                "URL_PATH_FILENAME",
                "URL_PATH_FOLDER",
                "USER_PROVIDED",
                "EXTENSION_PROVIDED",
                "UNKNOWN",
            )

        const val BACKEND_ID = "test-backend"

        const val EVIDENCE = "evidence-marker-present"

        const val HOST_SALT = "phase-28-05-fixed-salt"

        val RAW_REQUEST =
            "GET /basket HTTP/1.1\r\n" +
                "Host: shop.example\r\n" +
                "$POSITIVE_CONTROL_HEADER_BEFORE\r\n" +
                "Accept: text/html\r\n\r\n"

        /**
         * The payload `buildDetail` renders on its second controlled line.
         *
         * Hand-built ON PURPOSE, and the reason is the asymmetry `AiScanCheck.buildDetail`'s KDoc
         * records. Route 1's fixture is DERIVED from `PayloadGenerator.generateContextAwarePayloads`
         * because production builds route 1's payload that way, interpolating the operator's value.
         * `AiScanCheck` does NOT: it sources payloads from `getQuickPayloads`, which returns entries
         * from a static table and interpolates nothing (`PayloadGenerator.kt:633-639`). A derived
         * fixture here would therefore misrepresent the route it claims to measure — it would make
         * the payload line look like a carrier when at HEAD it is not one. The gate over that line
         * is defence in depth, and this fixture says so by carrying no trace of the sentinel.
         */
        val PAYLOAD =
            Payload(
                value = "' OR '1'='1",
                vulnClass = VulnClass.SQLI,
                detectionMethod = DetectionMethod.ERROR_BASED,
                risk = PayloadRisk.SAFE,
                expectedEvidence = EVIDENCE,
            )
    }
}
