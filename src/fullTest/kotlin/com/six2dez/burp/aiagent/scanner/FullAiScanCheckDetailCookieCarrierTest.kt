package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
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
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/** Serialized-tail guards split from AiScanCheckDetailCookieCarrierTest (D-16). */
class FullAiScanCheckDetailCookieCarrierTest {
    @BeforeEach
    fun clearCustomPatterns() {
        Redaction.setCustomPatterns(emptyList())
    }

    /**
     * SC1 for route 2, and THE DESIGNATED RED-PROBE ASSERTION for this plan (SC3).
     *
     * Both red probes recorded in `28-05-SUMMARY.md` are measured against THIS assertion: reverting
     * the control, and substituting the shared string-name predicate for the enum identity compare.
     * The second is the interesting one — it leaves the file compiling and reading as correct while
     * the control never fires.
     */
    @Test
    fun cookieBaseValueIsStrippedUnderStrict() {
        val detail = redactedDetailFor(cookieInsertionPoint(), PrivacyMode.STRICT)

        assertFalse(
            detail.contains(DETAIL_SENTINEL),
            "STRICT: a PARAM_COOKIE insertion point's baseValue() must be ABSENT from the redacted " +
                "`detail` field of an AiScanCheck-produced issue, but the sentinel " +
                "'$DETAIL_SENTINEL' was present. This is route 2 of AR-27-08 (CR-02): the value " +
                "reaches the scanner_issues MCP tool result through AuditIssue.detail(). Detail " +
                "was: $detail",
        )
        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "STRICT: the control must SUBSTITUTE the shared marker on the Original Value line, not " +
                "delete the line. An absence assertion alone cannot tell a working control from a " +
                "detail blob that was emptied — expected " +
                "'$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}'. " +
                "Detail was: $detail",
        )
        assertTrue(
            detail.contains(INSERTION_POINT_NAME),
            "STRICT: the insertion point's NAME must survive — names are not values. Its absence " +
                "would mean the whole line was destroyed rather than the value substituted, which " +
                "is the over-match regression class phase 27 round 4 shipped. Detail was: $detail",
        )
    }

    /** SC1 for route 2 under the other stripping mode. */
    @Test
    fun cookieBaseValueIsStrippedUnderBalanced() {
        val detail = redactedDetailFor(cookieInsertionPoint(), PrivacyMode.BALANCED)

        assertFalse(
            detail.contains(DETAIL_SENTINEL),
            "BALANCED: a PARAM_COOKIE insertion point's baseValue() must be ABSENT from the " +
                "redacted `detail` field, but the sentinel '$DETAIL_SENTINEL' was present. " +
                "RedactionPolicy.fromMode sets stripCookies = true for BALANCED as well as STRICT, " +
                "so a control that only fires under STRICT is keyed on the MODE rather than on the " +
                "policy. Detail was: $detail",
        )
        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}"),
            "BALANCED: the marker must be substituted on the Original Value line. Detail was: $detail",
        )
    }

    /**
     * SC2 for route 2 — the proof the control is POLICY-DRIVEN.
     *
     * This is the assertion that distinguishes a control from an unconditional rewrite, and it
     * carries extra weight here: before plan 28-05 this file read no privacy mode at all, so it
     * behaved identically in all three modes. A green STRICT assertion plus a green OFF assertion
     * is the pair that proves the mode is actually consulted.
     */
    @Test
    fun cookieBaseValueSurvivesUnderOff() {
        val detail = redactedDetailFor(cookieInsertionPoint(), PrivacyMode.OFF)

        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL"),
            "OFF: RedactionPolicy.fromMode(OFF) sets stripCookies = false, so the PARAM_COOKIE " +
                "point's baseValue() must survive VERBATIM as " +
                "'$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL'. If it does not, the STRICT and BALANCED " +
                "assertions above are vacuous: they would pass on output that never carried the " +
                "value in any mode. Detail was: $detail",
        )
    }

    /**
     * ATTRIBUTION CONTROL. A point carrying the IDENTICAL value under the IDENTICAL mode, differing
     * only in its type, must keep the value.
     *
     * Without this, a control that stripped every insertion point's value unconditionally would
     * satisfy every STRICT assertion above, and the "type-keyed" claim would be untested.
     */
    @Test
    fun urlParamInsertionPointSurvivesStrict_attributionControl() {
        val detail = redactedDetailFor(urlParamInsertionPoint(), PrivacyMode.STRICT)

        assertTrue(
            detail.contains("$ORIGINAL_VALUE_PREFIX$DETAIL_SENTINEL"),
            "STRICT: a PARAM_URL insertion point carrying the SAME value '$DETAIL_SENTINEL' must " +
                "keep it verbatim. The gate is keyed on AuditInsertionPointType.PARAM_COOKIE, and " +
                "D-28-01's pass-through for every other type is deliberate. Stripping here would " +
                "mean the control is not type-keyed at all, and the cookie assertions above would " +
                "prove nothing about the TYPE. Detail was: $detail",
        )
    }

    /**
     * The POSITIVE CONTROL, and it fires in the SAME STRICT output the detail assertion is made in.
     *
     * Without it, a null result inside `detail` would be attributable either to this plan's control
     * or to a dead pipeline — a `Redaction.apply` that silently did nothing, a serializer that
     * emitted an empty blob. The `Cookie:` header inside `requestResponses` is guarded by a
     * PRE-EXISTING rule that predates this phase, carries a value unrelated to [DETAIL_SENTINEL],
     * and is stripped in the same pass. The OFF half is what makes the STRICT half informative.
     */
    @Test
    fun theCookieHeaderPositiveControlFiresInTheSameStrictOutput() {
        val strictBlob = redactedBlobFor(cookieInsertionPoint(), PrivacyMode.STRICT)
        val offBlob = redactedBlobFor(cookieInsertionPoint(), PrivacyMode.OFF)

        assertTrue(
            requestFieldOf(offBlob).contains(POSITIVE_CONTROL_HEADER_BEFORE),
            "OFF: the raw request must carry '$POSITIVE_CONTROL_HEADER_BEFORE' before any rule " +
                "fires, or the STRICT assertion below is vacuous. Request was: " +
                requestFieldOf(offBlob),
        )
        assertFalse(
            requestFieldOf(strictBlob).contains(POSITIVE_CONTROL_COOKIE_VALUE),
            "STRICT: the PRE-EXISTING Cookie-header rule must have rewritten the header in the SAME " +
                "output as the detail assertion, but '$POSITIVE_CONTROL_COOKIE_VALUE' survived. " +
                "Without a firing positive control, the absence of the detail sentinel could be a " +
                "dead pipeline rather than this plan's control. Request was: " +
                requestFieldOf(strictBlob),
        )
        assertFalse(
            detailFieldOf(strictBlob).contains(DETAIL_SENTINEL),
            "STRICT: with the positive control confirmed firing in this same output, the detail " +
                "sentinel '$DETAIL_SENTINEL' must be absent and its absence is attributable to " +
                "AiScanCheck's own gate. Detail was: " + detailFieldOf(strictBlob),
        )
    }

    /**
     * NON-VACUITY of the absence assertions, measured in OFF — the only mode in which the sentinel
     * is present by design.
     *
     * An absence assertion over a TRUNCATED blob passes for free. This proves the sentinel sits well
     * inside the serialized output with substantial content after it, so "absent under STRICT" means
     * substituted rather than cut off.
     */
    @Test
    fun theSentinelIsNotTheTailOfTheSerializedBlob_nonVacuity() {
        val blob = redactedBlobFor(cookieInsertionPoint(), PrivacyMode.OFF)
        val sentinelIndex = blob.indexOf(DETAIL_SENTINEL)

        assertTrue(
            sentinelIndex >= 0,
            "NON-VACUITY: the sentinel '$DETAIL_SENTINEL' must be PRESENT in the OFF blob before " +
                "its position can be read as evidence. Blob was: $blob",
        )

        val tail = blob.substring(sentinelIndex + DETAIL_SENTINEL.length)
        assertTrue(
            tail.contains(TAIL_MARKER),
            "NON-VACUITY: the content after the sentinel must reach '$TAIL_MARKER', the last line " +
                "AiScanCheck.buildDetail writes. The tail was ${tail.length} chars and did not " +
                "reach it, so the blob is truncated and every absence assertion in this file could " +
                "be passing for free. Tail was: $tail",
        )
    }

    private fun cookieInsertionPoint(): AuditInsertionPoint = insertionPoint(AuditInsertionPointType.PARAM_COOKIE, DETAIL_SENTINEL)

    private fun urlParamInsertionPoint(): AuditInsertionPoint = insertionPoint(AuditInsertionPointType.PARAM_URL, DETAIL_SENTINEL)

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

    private fun issueDetailsFor(
        point: AuditInsertionPoint,
        mode: PrivacyMode,
    ): IssueDetails =
        IssueDetails(
            name = "[AI Active] ${VulnClass.SQLI.name} (Burp Scanner)",
            detail = detailFor(point, mode),
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

    private fun redactedBlobFor(
        point: AuditInsertionPoint,
        mode: PrivacyMode,
    ): String =
        Redaction.apply(
            toolJson.encodeToString(issueDetailsFor(point, mode)),
            RedactionPolicy.fromMode(mode),
            HOST_SALT,
        )

    private fun redactedDetailFor(
        point: AuditInsertionPoint,
        mode: PrivacyMode,
    ): String = detailFieldOf(redactedBlobFor(point, mode))

    private fun detailFieldOf(blob: String): String {
        val viaParse = runCatching { parsedOrNull(blob)?.get("detail")?.jsonPrimitive?.content }.getOrNull()
        return viaParse ?: fallbackStringField(blob, "detail")
    }

    private fun requestFieldOf(blob: String): String {
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

    private fun parsedOrNull(blob: String): JsonObject? = runCatching { Json.parseToJsonElement(blob).jsonObject }.getOrNull()

    /**
     * Substring fallback for the case where a redaction rule produced output that no longer parses
     * as JSON. Fails LOUDLY rather than returning an empty string, because a guard that silently
     * returned "" would turn every absence assertion in this file green.
     */
    private fun fallbackStringField(
        blob: String,
        key: String,
    ): String {
        val marker = "\"$key\":\""
        val start = blob.indexOf(marker)
        assertTrue(
            start >= 0,
            "EXTRACTOR: neither a JSON parse nor a substring scan located the `$key` field in the " +
                "redacted blob. Every guard downstream of this call measures nothing.",
        )
        val valueStart = start + marker.length
        var index = valueStart
        while (index < blob.length) {
            if (blob[index] == '"' && trailingBackslashCount(blob, index) % 2 == 0) {
                return blob.substring(valueStart, index)
            }
            index++
        }
        throw AssertionError(
            "EXTRACTOR: the `$key` field's opening quote was found but its closing quote was not. " +
                "The redacted blob is truncated or malformed.",
        )
    }

    private fun trailingBackslashCount(
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

        /**
         * The rendered prefix of the detail segment this plan's control owns, as route 2 spells it.
         * Since Phase 32 D-10 the detail is an HTML-escaped, `<br>`-joined line list; the fixture
         * values contain no `&`, `<` or `>`, so the escaping leaves them byte-identical.
         */
        const val ORIGINAL_VALUE_PREFIX = "Original Value: "

        /**
         * The last line `AiScanCheck.buildDetail` writes, used as the non-vacuity tail marker. No
         * digits, no dots: nothing another redaction rule can plausibly claim, so its presence in
         * the tail measures the FIXTURE's shape rather than some rule's behaviour.
         */
        const val TAIL_MARKER = "Confirmed via active exploitation testing"

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
