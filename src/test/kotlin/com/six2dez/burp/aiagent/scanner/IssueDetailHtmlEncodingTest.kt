package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCategory
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptConfidence
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptDefinition
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptFinding
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptOutputType
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.UiActions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 32 SC4 / SCAN-02 / D-10 / D-11: every issue detail the extension builds renders a payload,
 * a target-derived value or AI-generated text as LITERAL TEXT in Burp's issue view, never as markup.
 *
 * D-10 fixes one format and one escaping path for every issue the extension creates:
 * `IssueUtils.formatIssueDetailHtml` (escape `&`, `<`, `>`, join with `<br>`). D-11 asks for the
 * check on the GENERATED detail, fed with markup through the payload and the target-derived values,
 * so each producer case below calls the real producer function and inspects the string it returns.
 *
 * WHAT THIS FILE IS NOT. It is an ESCAPING test. It says nothing about cookie values, and it is NOT
 * the repository-wide single-producer cookie gate that `D-28-06` / `WR-01` describe: those stay
 * NAMED RESIDUALS, and no artifact may cite this class as closing either of them. The PRIV-05 probes
 * for route 2 live in `AiScanCheckDetailCookieCarrierTest`.
 *
 * Producers covered here: `AiScanCheck.buildDetail` (AI Active via Burp Scanner) and
 * `UiActions.buildIssueDetailHtml` (BountyPrompt). Plan 32-04 adds the remaining producers and the
 * producer census to this class, reusing [assertHtmlSafe] and [MARKUP].
 */
class IssueDetailHtmlEncodingTest {
    // =============================================================================================
    // AiScanCheck.buildDetail (route 2, AI Active via Burp Scanner)
    // =============================================================================================

    @Test
    fun aiScanCheckDetailRendersMarkupAsLiteralTextUnderStrict() {
        val detail = aiScanCheckDetail(markupPoint(), payloadWithValue(MARKUP), MARKUP, PrivacyMode.STRICT)

        assertHtmlSafe(detail, AI_SCAN_CHECK)
        assertCarriesEscapedMarkup(detail, AI_SCAN_CHECK)
    }

    @Test
    fun aiScanCheckDetailRendersMarkupAsLiteralTextUnderOff() {
        val detail = aiScanCheckDetail(markupPoint(), payloadWithValue(MARKUP), MARKUP, PrivacyMode.OFF)

        assertHtmlSafe(detail, AI_SCAN_CHECK)
        assertCarriesEscapedMarkup(detail, AI_SCAN_CHECK)
    }

    /** [edge:adjacency] An already-escaped value is escaped again, so it can never be decoded. */
    @Test
    fun aiScanCheckDetailEscapesAnAlreadyEscapedPayloadAgain() {
        val detail = aiScanCheckDetail(plainPoint(), payloadWithValue("&lt;b&gt;"), PLAIN_EVIDENCE, PrivacyMode.STRICT)

        assertHtmlSafe(detail, AI_SCAN_CHECK)
        assertTrue(
            segmentsOf(detail).contains("Payload Used: &amp;lt;b&amp;gt;"),
            "$AI_SCAN_CHECK: an already-escaped payload '&lt;b&gt;' must render as " +
                "'Payload Used: &amp;lt;b&amp;gt;' so Burp shows the entity text, not a tag. Detail was: $detail",
        )
    }

    /** [edge:adjacency] A payload carrying the text `<br>` cannot forge a line break. */
    @Test
    fun aiScanCheckDetailPayloadCannotForgeALineBreak() {
        val detail = aiScanCheckDetail(plainPoint(), payloadWithValue("x<br>y"), PLAIN_EVIDENCE, PrivacyMode.STRICT)

        assertHtmlSafe(detail, AI_SCAN_CHECK)
        assertTrue(
            segmentsOf(detail).contains("Payload Used: x&lt;br&gt;y"),
            "$AI_SCAN_CHECK: a payload 'x<br>y' must render as 'Payload Used: x&lt;br&gt;y' inside ONE " +
                "segment. A raw <br> would split the payload into a forged extra line. Detail was: $detail",
        )
    }

    /** [edge:empty] An empty payload and an empty evidence still render their segments. */
    @Test
    fun aiScanCheckDetailRendersEmptyPayloadAndEvidenceSegments() {
        val detail = aiScanCheckDetail(plainPoint(), payloadWithValue(""), "", PrivacyMode.STRICT)
        val segments = segmentsOf(detail)

        assertHtmlSafe(detail, AI_SCAN_CHECK)
        assertTrue(
            segments.contains("Payload Used: "),
            "$AI_SCAN_CHECK: an empty payload must still render the 'Payload Used: ' segment. Segments: $segments",
        )
        assertTrue(
            segments.contains("Evidence: "),
            "$AI_SCAN_CHECK: an empty evidence must still render the 'Evidence: ' segment. Segments: $segments",
        )
    }

    /** [edge:ordering] The labelled segments keep their order, and the payload owns one segment. */
    @Test
    fun aiScanCheckDetailKeepsTheSegmentOrder() {
        val detail = aiScanCheckDetail(plainPoint(), payloadWithValue(PLAIN_PAYLOAD), PLAIN_EVIDENCE, PrivacyMode.STRICT)
        val segments = segmentsOf(detail)

        val indices =
            ORDERED_PREFIXES.map { prefix ->
                val index = segments.indexOfFirst { it.startsWith(prefix) }
                assertTrue(index >= 0, "$AI_SCAN_CHECK: no segment starts with '$prefix'. Segments: $segments")
                index
            }
        assertEquals(
            indices.sorted(),
            indices,
            "$AI_SCAN_CHECK: the segments must appear in the order $ORDERED_PREFIXES. Found them at " +
                "$indices. Segments: $segments",
        )
        assertTrue(
            indices.last() < segments.lastIndex && segments.last().contains(TAIL_TEXT),
            "$AI_SCAN_CHECK: the last segment must carry '$TAIL_TEXT' and come after every labelled " +
                "segment. Segments: $segments",
        )
        assertEquals(
            1,
            segments.count { it.startsWith(PAYLOAD_PREFIX) },
            "$AI_SCAN_CHECK: exactly one segment may start with '$PAYLOAD_PREFIX'. Segments: $segments",
        )
    }

    /** [edge:ordering] A real CR/LF in the payload stays inside the payload's own segment. */
    @Test
    fun aiScanCheckDetailKeepsACrLfPayloadInsideItsSegment() {
        val plain = segmentsOf(aiScanCheckDetail(plainPoint(), payloadWithValue("ab"), PLAIN_EVIDENCE, PrivacyMode.STRICT))
        val crlfDetail = aiScanCheckDetail(plainPoint(), payloadWithValue("a\r\nb"), PLAIN_EVIDENCE, PrivacyMode.STRICT)
        val crlf = segmentsOf(crlfDetail)

        assertHtmlSafe(crlfDetail, AI_SCAN_CHECK)
        assertEquals(
            plain.size,
            crlf.size,
            "$AI_SCAN_CHECK: a payload with a real CR/LF must not add segments. Plain: $plain CR/LF: $crlf",
        )
        assertEquals(
            listOf("Payload Used: a\r\nb"),
            crlf.filter { it.startsWith(PAYLOAD_PREFIX) },
            "$AI_SCAN_CHECK: the CR/LF payload must stay whole inside its one 'Payload Used: ' segment. Segments: $crlf",
        )
    }

    // =============================================================================================
    // UiActions.buildIssueDetailHtml (BountyPrompt)
    // =============================================================================================

    /** Markup in the AI-generated finding detail and in the prompt title renders as literal text. */
    @Test
    fun bountyPromptDetailRendersMarkupAsLiteralText() {
        val detail = UiActions.buildIssueDetailHtml(bountyPromptDefinition("p1", MARKUP), bountyPromptFinding(MARKUP))

        assertHtmlSafe(detail, BOUNTY_PROMPT)
        assertCarriesEscapedMarkup(detail, BOUNTY_PROMPT)
    }

    /** Delegating to the shared formatter leaves the BountyPrompt detail format byte-identical. */
    @Test
    fun bountyPromptDetailFormatIsUnchanged() {
        val detail = UiActions.buildIssueDetailHtml(bountyPromptDefinition("p1", "T"), bountyPromptFinding("x & <y>"))
        val expectedStart =
            "x &amp; &lt;y&gt;<br><br>AI Analysis Metadata<br>&nbsp;&nbsp;Source: BountyPrompt" +
                "<br>&nbsp;&nbsp;Prompt ID: p1<br>&nbsp;&nbsp;Prompt Title: T"

        assertTrue(
            detail.startsWith(expectedStart),
            "$BOUNTY_PROMPT: the detail must start with '$expectedStart'. Detail was: $detail",
        )
        assertTrue(
            detail.contains("<br>&nbsp;&nbsp;Parsed Confidence: 70%<br>"),
            "$BOUNTY_PROMPT: the parsed confidence segment must render as before. Detail was: $detail",
        )
    }

    private fun bountyPromptDefinition(
        id: String,
        title: String,
    ): BountyPromptDefinition =
        BountyPromptDefinition(
            id = id,
            title = title,
            category = BountyPromptCategory.DETECTION,
            outputType = BountyPromptOutputType.ISSUE,
            systemPrompt = "system",
            userPrompt = "user",
            severity = "Medium",
            confidence = BountyPromptConfidence.FIRM,
            tagsUsed = emptySet(),
        )

    private fun bountyPromptFinding(detail: String): BountyPromptFinding =
        BountyPromptFinding(title = "finding", detail = detail, severity = "Medium", confidence = BOUNTY_FINDING_CONFIDENCE)

    // ---------------------------------------------------------------------------------------------
    // AiScanCheck harness (same shape as AiScanCheckDetailCookieCarrierTest)
    // ---------------------------------------------------------------------------------------------

    private fun aiScanCheckDetail(
        point: AuditInsertionPoint,
        payload: Payload,
        evidence: String,
        mode: PrivacyMode,
    ): String = AiScanCheck(mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)) { settingsFor(mode) }.buildDetail(point, payload, evidence)

    private fun settingsFor(mode: PrivacyMode): AgentSettings =
        AgentSettingsRepository(mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS))
            .defaultSettings()
            .copy(privacyMode = mode, preferredBackendId = BACKEND_ID)

    /** A PARAM_URL point whose name and base value both carry [MARKUP]. */
    private fun markupPoint(): AuditInsertionPoint = insertionPoint("q$MARKUP", MARKUP)

    private fun plainPoint(): AuditInsertionPoint = insertionPoint("q", "plain-base-value")

    private fun insertionPoint(
        name: String,
        baseValue: String,
    ): AuditInsertionPoint {
        val point = mock<AuditInsertionPoint>()
        whenever(point.name()).thenReturn(name)
        whenever(point.baseValue()).thenReturn(baseValue)
        whenever(point.type()).thenReturn(AuditInsertionPointType.PARAM_URL)
        return point
    }

    private fun payloadWithValue(value: String): Payload =
        Payload(
            value = value,
            vulnClass = VulnClass.XSS_REFLECTED,
            detectionMethod = DetectionMethod.REFLECTION,
            risk = PayloadRisk.SAFE,
            expectedEvidence = PLAIN_EVIDENCE,
        )

    private companion object {
        const val AI_SCAN_CHECK = "AiScanCheck.buildDetail"
        const val BOUNTY_PROMPT = "UiActions.buildIssueDetailHtml"
        const val BOUNTY_FINDING_CONFIDENCE = 70

        /** Script tag, attribute break-out with an event handler, and a bare ampersand. */
        const val MARKUP = "<script>alert(1)</script> \"><img src=x onerror=alert(1)> a&b"

        const val BACKEND_ID = "test-backend"
        const val PLAIN_PAYLOAD = "plain-payload"
        const val PLAIN_EVIDENCE = "plain-evidence"
        const val PAYLOAD_PREFIX = "Payload Used: "
        const val TAIL_TEXT = "Confirmed via active exploitation testing"

        val ORDERED_PREFIXES =
            listOf(
                "Insertion Point: ",
                "Original Value: ",
                PAYLOAD_PREFIX,
                "Detection Method: ",
                "Evidence: ",
                "Risk Level: ",
                "AI Analysis Metadata",
            )

        /** The only `&` sequences an escaped detail may contain. */
        val ALLOWED_ENTITIES = listOf("&amp;", "&lt;", "&gt;", "&nbsp;")

        const val LINE_BREAK = "<br>"
        const val CONTEXT_RADIUS = 20

        fun segmentsOf(detail: String): List<String> = detail.split(LINE_BREAK)

        /**
         * The structural markup check shared by every producer case: no raw `<script` or `<img`, every
         * `<` starts the `<br>` separator, and every `&` starts one of [ALLOWED_ENTITIES]. The failure
         * message names the producer and quotes the offending index and its context.
         */
        fun assertHtmlSafe(
            detail: String,
            producer: String,
        ) {
            listOf("<script", "<img").forEach { tag ->
                val index = detail.indexOf(tag, ignoreCase = true)
                assertTrue(index < 0, "$producer: raw '$tag' at index $index: '${contextAt(detail, index)}'")
            }
            detail.indices.filter { detail[it] == '<' }.forEach { index ->
                assertTrue(
                    detail.startsWith(LINE_BREAK, index),
                    "$producer: a '<' at index $index does not start '$LINE_BREAK': '${contextAt(detail, index)}'",
                )
            }
            detail.indices.filter { detail[it] == '&' }.forEach { index ->
                assertTrue(
                    ALLOWED_ENTITIES.any { detail.startsWith(it, index) },
                    "$producer: an '&' at index $index starts none of $ALLOWED_ENTITIES: '${contextAt(detail, index)}'",
                )
            }
        }

        /** The positive half: [MARKUP] reached the detail, escaped. */
        fun assertCarriesEscapedMarkup(
            detail: String,
            producer: String,
        ) {
            listOf("&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img src=x onerror=alert(1)&gt;", "a&amp;b").forEach {
                assertTrue(detail.contains(it), "$producer: the detail must contain '$it'. Detail was: $detail")
            }
        }

        fun contextAt(
            detail: String,
            index: Int,
        ): String = detail.substring((index - CONTEXT_RADIUS).coerceAtLeast(0), (index + CONTEXT_RADIUS).coerceAtMost(detail.length))
    }
}
