package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType
import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.tools.CreateAuditIssue
import com.six2dez.burp.aiagent.mcp.tools.executeIssueCreate
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptCategory
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptConfidence
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptDefinition
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptFinding
import com.six2dez.burp.aiagent.prompts.bountyprompt.BountyPromptOutputType
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.ui.UiActions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.io.File
import java.lang.reflect.InvocationTargetException
import burp.api.montoya.core.ByteArray as MontoyaByteArray

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
 * Producers covered here (D-12: every producer, no exception), each with its own markup case:
 *  - `scanner/AiScanCheck.kt`: `AiScanCheck.buildDetail` (AI Active via Burp Scanner), `aiScanCheckDetail*`.
 *  - `ui/UiActions.kt`: `UiActions.buildIssueDetailHtml` (BountyPrompt), `bountyPromptDetail*`.
 *  - `scanner/AiPassiveScanCheck.kt`: local passive findings, a markup Content-Length driven through
 *    the real scan check, `aiPassiveScanCheckLocalFinding*`.
 *  - `scanner/PassiveAiScannerFinding.kt`: AI passive findings via `handleParsedAiIssues`,
 *    `aiPassiveFindingDetail*`.
 *  - `scanner/ActiveAiScanner.kt`: the case drives the real private `createConfirmedIssue` itself, by
 *    reflection, and checks the issue it files, `activeScannerConfirmedIssue*`.
 *  - `mcp/tools/IssueCreateSupport.kt`: the native MCP `issue_create` tool, all four text fields,
 *    `issueCreate*`.
 *
 * The producer census ([everyIssueProducerIsKnownAndCallsTheSharedFormatter]) pins that set of files
 * and requires `IssueUtils.formatIssueDetailHtml(` in each. A new producer joins the census only
 * with a markup case of its own in this class. The census is an escaping census too: it is not the
 * D-28-06 / WR-01 cookie single-producer gate and must not be cited as closing it.
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

    // =============================================================================================
    // AiPassiveScanCheck (local passive findings filed through Burp Scanner)
    // =============================================================================================

    /**
     * Research Pitfall 6: a target-supplied Content-Length value reaches the local finding's detail.
     * Burp receives it escaped and `<br>`-joined; the findings buffer keeps the raw detail.
     */
    @Test
    fun aiPassiveScanCheckLocalFindingRendersATargetValueAsLiteralText() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)
            val rr = rig.duplicateContentLengthGet("enc-local.example", MARKUP_CL)

            val result = rig.check.doCheck(rr)
            rig.drain()

            assertEquals(
                listOf("[AI Passive] REQUEST_SMUGGLING"),
                result.auditIssues().map { it.name() },
                "$AI_PASSIVE_SCAN_CHECK: the duplicate Content-Length request files one smuggling issue",
            )
            val detail = rig.built.single().detail
            assertHtmlSafe(detail, AI_PASSIVE_SCAN_CHECK)
            assertEquals(
                1,
                detail.split(LINE_BREAK).size - 1,
                "$AI_PASSIVE_SCAN_CHECK: the two detail lines are joined by exactly one '$LINE_BREAK'. Detail was: $detail",
            )
            assertTrue(
                detail.contains(MARKUP_CL_ESCAPED),
                "$AI_PASSIVE_SCAN_CHECK: the detail must carry '$MARKUP_CL_ESCAPED'. Detail was: $detail",
            )

            val rawDetail =
                rig.scanner
                    .localChecks(rr.request(), rr.response())
                    .single()
                    .detail
            val buffered =
                rig.scanner
                    .getLastFindings(1)
                    .single()
                    .detail
            assertEquals(rawDetail, buffered, "$AI_PASSIVE_SCAN_CHECK: the findings buffer keeps the raw LocalFinding.detail")
            assertTrue(
                buffered.contains("<script>"),
                "$AI_PASSIVE_SCAN_CHECK: the buffered detail is the raw text, not the escaped one. Buffered: $buffered",
            )
        }
    }

    // =============================================================================================
    // PassiveAiScannerFinding (AI passive findings: handleParsedAiIssues -> handleFinding)
    // =============================================================================================

    @Test
    fun aiPassiveFindingDetailRendersMarkupAsLiteralText() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.handleParsedAiIssues(
                listOf(
                    AiIssueItem(
                        title = "SQL Injection",
                        severity = "High",
                        detail = MARKUP + "\nsecond line " + MARKUP,
                        confidence = AI_FINDING_CONFIDENCE,
                    ),
                ),
                rig.csrfPost("enc-ai.example"),
                "LOW",
            )

            val detail = rig.built.single().detail
            assertHtmlSafe(detail, AI_PASSIVE_FINDING)
            assertCarriesEscapedMarkup(detail, AI_PASSIVE_FINDING)
        }
    }

    // =============================================================================================
    // ActiveAiScanner (the real createConfirmedIssue, driven by reflection)
    // =============================================================================================

    /**
     * 32-REVIEW WR-03: the case runs the producer itself, so a change inside `createConfirmedIssue`
     * that appends raw text after formatting fails here. Markup reaches the injection point name and
     * value, the payload and the evidence.
     */
    @Test
    fun activeScannerConfirmedIssueRendersMarkupAsLiteralText() {
        PassiveScanCheckRig().use { rig ->
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            try {
                val original = rig.csrfPost("enc-active.example")
                val confirmation =
                    VulnConfirmation(
                        target =
                            ActiveScanTarget(
                                originalRequest = original,
                                injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "q$MARKUP", MARKUP),
                                vulnHint = VulnHint(VulnClass.SQLI, ACTIVE_HINT_CONFIDENCE, MARKUP),
                                priority = ACTIVE_TARGET_PRIORITY,
                            ),
                        payload = Payload(MARKUP, VulnClass.SQLI, DetectionMethod.ERROR_BASED, PayloadRisk.SAFE, MARKUP),
                        originalResponse = original,
                        exploitResponse = exploitPair(),
                        confidence = ACTIVE_CONFIRMATION_CONFIDENCE,
                        evidence = MARKUP,
                        confirmed = true,
                    )

                createConfirmedIssue(active, confirmation)

                assertEquals(
                    listOf("[AI Active] SQLI"),
                    rig.built.map { it.name },
                    "$ACTIVE_SCANNER must file exactly one issue. Errors logged: ${rig.errors}",
                )
                assertEquals(
                    1,
                    rig.extensionAdds.size,
                    "$ACTIVE_SCANNER must add its issue to the site map once. Errors logged: ${rig.errors}",
                )
                assertEquals(
                    emptyList<String>(),
                    rig.errors.toList(),
                    "$ACTIVE_SCANNER logged an error; its catch hides a failure (for example a mock NPE)",
                )
                val detail = rig.built.single().detail
                assertHtmlSafe(detail, ACTIVE_SCANNER)
                assertCarriesEscapedMarkup(detail, ACTIVE_SCANNER)
            } finally {
                active.shutdown()
            }
        }
    }

    // =============================================================================================
    // issue_create (native MCP tool: IssueCreateSupport.executeIssueCreate)
    // =============================================================================================

    /**
     * D-12: an agent can echo prompt-injected target text into issue_create. Every text field Burp
     * renders as HTML (detail, remediation, background, remediation background) arrives escaped,
     * after IssueText.sanitize has stripped the Markdown.
     */
    @Test
    fun issueCreateEscapesEveryTextFieldAnAgentSends() {
        PassiveScanCheckRig().use { rig ->
            val result =
                executeIssueCreate(
                    CreateAuditIssue(
                        name = "Reflected XSS",
                        detail = MARKUP + "\n**bold** line",
                        baseUrl = "https://enc-mcp.example/a",
                        severity = "HIGH",
                        confidence = "FIRM",
                        remediation = MARKUP,
                        background = MARKUP,
                        remediationBackground = MARKUP,
                    ),
                    rig.api,
                    mcpContext(rig.api),
                )

            assertTrue(result.startsWith("Issue created: "), "$ISSUE_CREATE: unexpected result '$result'")
            val filed = rig.built.single()
            mapOf(
                "detail" to filed.detail,
                "remediation" to filed.remediation,
                "background" to filed.background,
                "remediationBackground" to filed.remediationBackground,
            ).forEach { (field, value) ->
                val text = requireNotNull(value) { "$ISSUE_CREATE: $field reached Burp as null" }
                assertHtmlSafe(text, "$ISSUE_CREATE $field")
                assertCarriesEscapedMarkup(text, "$ISSUE_CREATE $field")
            }
            val segments = segmentsOf(filed.detail)
            assertEquals(
                2,
                segments.size,
                "$ISSUE_CREATE: the detail's two lines are joined by one '$LINE_BREAK'. Segments: $segments",
            )
            assertEquals("bold line", segments.last(), "$ISSUE_CREATE: the Markdown is stripped before escaping")
        }
    }

    /** With no optional text, remediation, background and remediation background stay empty. */
    @Test
    fun issueCreateLeavesAbsentOptionalTextEmpty() {
        PassiveScanCheckRig().use { rig ->
            val result =
                executeIssueCreate(
                    CreateAuditIssue(
                        name = "Plain finding",
                        detail = "plain detail",
                        baseUrl = "https://enc-mcp-empty.example/a",
                        severity = "LOW",
                        confidence = "TENTATIVE",
                    ),
                    rig.api,
                    mcpContext(rig.api),
                )

            assertTrue(result.startsWith("Issue created: "), "$ISSUE_CREATE: unexpected result '$result'")
            val filed = rig.built.single()
            assertEquals("plain detail", filed.detail)
            assertEquals("", filed.remediation)
            assertEquals("", filed.background)
            assertEquals("", filed.remediationBackground)
        }
    }

    // =============================================================================================
    // Producer census (D-11 / D-12)
    // =============================================================================================

    /**
     * Every production file that builds an AuditIssue is a known producer, and every producer calls
     * the shared formatter. A new producer file, or a producer that drops the call, fails here.
     * The behavioral cases above catch a producer that keeps the call but bypasses it.
     */
    @Test
    fun everyIssueProducerIsKnownAndCallsTheSharedFormatter() {
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the source walk reached ${files.size} .kt files under ${SourceRoots.PRODUCTION}, below the floor " +
                "of $MIN_EXPECTED_MAIN_FILES. A walk that reaches nothing reports a clean tree; fix the walk first.",
        )

        val producers =
            files
                .filter { file -> codeLines(file).any { AUDIT_ISSUE_CALL.containsMatchIn(it) } }
                .associateBy { SourceRoots.packageRelativePath(it) }

        assertEquals(
            KNOWN_PRODUCERS,
            producers.keys,
            "the set of production files with a non-comment auditIssue( call changed. Unexpected: " +
                "${producers.keys - KNOWN_PRODUCERS}; missing: ${KNOWN_PRODUCERS - producers.keys}. A new " +
                "producer must route its detail through IssueUtils.formatIssueDetailHtml and add a markup " +
                "case of its own to this class before it joins KNOWN_PRODUCERS.",
        )
        val nonEscaping =
            producers.filterValues { file -> codeLines(file).none { it.contains(FORMATTER_CALL) } }.keys
        assertEquals(
            emptySet<String>(),
            nonEscaping,
            "these producers never call $FORMATTER_CALL. Route the issue detail through " +
                "IssueUtils.formatIssueDetailHtml and add a markup case for the producer to this class.",
        )
    }

    private fun mcpContext(api: MontoyaApi): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.STRICT,
            determinismMode = false,
            hostSalt = "test-salt",
            toolToggles = emptyMap(),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(MCP_LIMIT),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = MCP_MAX_BODY_BYTES,
        )

    /**
     * Runs the real `ActiveAiScanner.createConfirmedIssue`, the TargetTrafficTlsTest.executeScan way.
     * Reflection, not a visibility change: the function is private, and its LongMethod detekt baseline
     * entry is keyed on that private signature, so widening it would break detekt (ADR-17 forbids new
     * baseline entries). A rename fails loudly here with NoSuchMethodException.
     */
    private fun createConfirmedIssue(
        scanner: ActiveAiScanner,
        confirmation: VulnConfirmation,
    ) {
        val method = ActiveAiScanner::class.java.getDeclaredMethod("createConfirmedIssue", VulnConfirmation::class.java)
        method.isAccessible = true
        try {
            method.invoke(scanner, confirmation)
        } catch (e: InvocationTargetException) {
            throw e.cause ?: e
        }
    }

    /**
     * The exploit pair `createConfirmedIssue` marks: its request bytes hold no [MARKUP], so
     * `markRequestPayload` finds nothing to mark, and its response is null, so `markResponseEvidence`
     * returns the pair unchanged.
     */
    private fun exploitPair(): HttpRequestResponse {
        val bytes = mock<MontoyaByteArray> { on { getBytes() } doReturn EXPLOIT_REQUEST.toByteArray(Charsets.ISO_8859_1) }
        val request = mock<HttpRequest> { on { toByteArray() } doReturn bytes }
        return mock {
            on { request() } doReturn request
            on { response() } doReturn null
        }
    }

    /**
     * WR-03: a file that already calls the formatter once must still fail when it gains a second,
     * raw `auditIssue(`. Proven on synthetic source lines, so no production file is touched.
     */
    @Test
    fun theCensusCatchesASecondRawProducerInAFileThatAlreadyEscapes() {
        val secondRaw =
            listOf(
                "val a = IssueUtils.formatIssueDetailHtml(x)",
                "AuditIssue.auditIssue(n, a)",
                "AuditIssue.auditIssue(n, raw)",
            )
        val caught = producerCensus(secondRaw)
        assertNotNull(
            caught.violation,
            "two auditIssue( calls and one formatter call must be reported. Counted: $caught",
        )
        assertEquals(SECOND_RAW_PRODUCERS, caught.auditIssueCalls, "both auditIssue( calls count. Counted: $caught")
        assertEquals(1, caught.formatterCalls, "the one formatter call counts. Counted: $caught")

        val sameLine = producerCensus(listOf(secondRaw[0], "${secondRaw[1]}; ${secondRaw[2]}"))
        assertEquals(SECOND_RAW_PRODUCERS, sameLine.auditIssueCalls, "two calls on ONE line count twice. Counted: $sameLine")
        assertNotNull(sameLine.violation, "two calls on one line with one formatter call must be reported")

        val fixed = producerCensus(secondRaw + "val b = IssueUtils.formatIssueDetailHtml(y)")
        assertNull(fixed.violation, "a second formatter call settles the second producer. Counted: $fixed")

        val commented = producerCensus(secondRaw + "val b = IssueUtils.formatIssueDetailHtml(y)" + COMMENTED_PRODUCERS)
        assertEquals(fixed, commented, "comment lines must not change the counts or the verdict")
        assertEquals(
            ProducerCensus(0, 0, null),
            producerCensus(COMMENTED_PRODUCERS),
            "comment-only auditIssue( lines are not producers",
        )
    }

    /**
     * The escaping census for one file's source lines: the non-comment `auditIssue(` calls, the
     * non-comment [FORMATTER_CALL] calls, and a violation description when the file breaks the rule.
     */
    private fun producerCensus(lines: List<String>): ProducerCensus {
        val code = codeLines(lines)
        val producers = code.count { AUDIT_ISSUE_CALL.containsMatchIn(it) }
        val formatters = code.count { it.contains(FORMATTER_CALL) }
        val violation = if (producers > 0 && formatters == 0) "never calls $FORMATTER_CALL" else null
        return ProducerCensus(producers, formatters, violation)
    }

    private fun codeLines(file: File): List<String> = codeLines(file.readText(Charsets.UTF_8).lines())

    /**
     * The lines without comment lines: a line whose trimmed text starts with one of
     * [COMMENT_PREFIXES] (a KDoc star, a line comment or a block-comment opener).
     */
    private fun codeLines(lines: List<String>): List<String> =
        lines.filterNot { line ->
            val trimmed = line.trimStart()
            COMMENT_PREFIXES.any { trimmed.startsWith(it) }
        }

    /** One file's escaping-census counts over its non-comment lines, and its violation, if any. */
    private data class ProducerCensus(
        val auditIssueCalls: Int,
        val formatterCalls: Int,
        val violation: String?,
    )

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

    private fun bountyPromptFinding(detail: String): BountyPromptFinding = BountyPromptFinding(title = "finding", detail = detail, severity = "Medium", confidence = BOUNTY_FINDING_CONFIDENCE)

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
        const val AI_PASSIVE_SCAN_CHECK = "AiPassiveScanCheck.doCheck"
        const val AI_PASSIVE_FINDING = "PassiveAiScannerFinding.handleFinding"
        const val ACTIVE_SCANNER = "ActiveAiScanner.createConfirmedIssue"
        const val ACTIVE_HINT_CONFIDENCE = 90
        const val ACTIVE_TARGET_PRIORITY = 80
        const val ACTIVE_CONFIRMATION_CONFIDENCE = 96
        const val EXPLOIT_REQUEST = "GET /enc-active HTTP/1.1\r\n\r\n"
        const val AI_FINDING_CONFIDENCE = 90
        const val ISSUE_CREATE = "IssueCreateSupport.executeIssueCreate"
        const val MCP_LIMIT = 4
        const val MCP_MAX_BODY_BYTES = 8192

        /** Non-vacuity floor for the census walk over the production roots. */
        const val MIN_EXPECTED_MAIN_FILES = 150

        /** Package-relative paths of every production file that builds an AuditIssue (D-12). */
        val KNOWN_PRODUCERS =
            setOf(
                "scanner/AiScanCheck.kt",
                "scanner/ActiveAiScanner.kt",
                "scanner/PassiveAiScannerFinding.kt",
                "scanner/AiPassiveScanCheck.kt",
                "ui/UiActions.kt",
                "mcp/tools/IssueCreateSupport.kt",
            )
        val AUDIT_ISSUE_CALL = Regex("""\bauditIssue\(""")
        const val FORMATTER_CALL = "IssueUtils.formatIssueDetailHtml("
        val COMMENT_PREFIXES = listOf("*", "//", "/*")
        const val SECOND_RAW_PRODUCERS = 2
        val COMMENTED_PRODUCERS = listOf(" * AuditIssue.auditIssue(", "// auditIssue(")
        const val BOUNTY_FINDING_CONFIDENCE = 70

        /** Script tag, attribute break-out with an event handler, and a bare ampersand. */
        const val MARKUP = "<script>alert(1)</script> \"><img src=x onerror=alert(1)> a&b"

        /** A header-safe single-line markup value for the duplicate Content-Length request. */
        const val MARKUP_CL = "<script>alert(1)</script>&<img src=x onerror=alert(1)>"
        const val MARKUP_CL_ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;&amp;&lt;img src=x onerror=alert(1)&gt;"

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
