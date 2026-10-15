package com.six2dez.burp.aiagent.util

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
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
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.scanner.AiIssueItem
import com.six2dez.burp.aiagent.scanner.PassiveScanCheckRig
import com.six2dez.burp.aiagent.scanner.handleParsedAiIssues
import com.six2dez.burp.aiagent.ui.UiActions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 32 gap closure (32-REVIEW CR-01, SCAN-02): [IssueText.sanitize] strips Markdown so Burp
 * shows plain text, but it must keep an underscore that sits between two letters or digits.
 * Parameter and header names such as `access_token` and `session_id` are what read-time privacy
 * redaction keys on. Before this change every underscore was dropped, so `access_token=<v>` was
 * filed as `accesstoken=<v>` and no redaction rule recognized the key any more.
 *
 * Survival-sweep discipline: a function that names a redacting mode asserts ABSENCE only. The one
 * presence check on a sentinel lives in [offControlKeepsTheSentinel], which names only
 * `PrivacyMode.OFF` and reaches the policy through [redactUnder].
 */
class IssueTextTest {
    // ---------------------------------------------------------------------------------------------
    // Key survival and redaction attribution (Task 1)
    // ---------------------------------------------------------------------------------------------

    /** An agent's issue_create detail keeps the key `access_token`, escaped but intact. */
    @Test
    fun issueCreateDetailKeepsAccessTokenKey() {
        PassiveScanCheckRig().use { rig ->
            val result =
                executeIssueCreate(
                    CreateAuditIssue(
                        name = "Token in URL",
                        detail = "Observed request:\nGET /api?page=1&access_token=sentineltokenissuetext",
                        baseUrl = "https://issuetext.example/api",
                        severity = "HIGH",
                        confidence = "FIRM",
                    ),
                    rig.api,
                    offContext(rig.api),
                )

            assertTrue(result.startsWith("Issue created: "), "unexpected issue_create result '$result'")
            val detail = rig.built.single().detail
            assertTrue(
                detail.contains("&amp;access_token="),
                "the filed detail must keep the key access_token (escaped as &amp;access_token=). Detail was: $detail",
            )
        }
    }

    /**
     * The plain-text form of a sanitized detail is redacted under STRICT and BALANCED, because the
     * key `access_token` survives the Markdown strip. Before the change the key reached redaction as
     * `accesstoken` and the value was left in place.
     */
    @Test
    fun sanitizedAccessTokenIsRedactedUnderStrictAndBalanced() {
        listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED).forEach { mode ->
            val redacted = redactUnder(mode, IssueText.sanitize(ATTRIBUTION_TEXT))
            assertFalse(
                redacted.contains("sentineltokenattribution"),
                "$mode: the access_token value must be redacted after IssueText.sanitize. Output was: $redacted",
            )
        }
    }

    /** OFF control: the same text keeps the value, so the absence above comes from redaction. */
    @Test
    fun offControlKeepsTheSentinel() {
        val output = redactUnder(PrivacyMode.OFF, IssueText.sanitize(ATTRIBUTION_TEXT))
        assertTrue(
            output.contains("sentineltokenattribution"),
            "OFF must not redact; the absence under the redacting modes would otherwise prove nothing. Output: $output",
        )
    }

    @Test
    fun emphasisUnderscoresAndAsterisksAreRemoved() {
        assertEquals(
            "italic and bold and strong and em",
            IssueText.sanitize("_italic_ and __bold__ and **strong** and *em*"),
        )
    }

    @Test
    fun intraWordUnderscoresAreKept() {
        val input = "access_token session_id X_Frame_Options a__b"
        assertEquals(input, IssueText.sanitize(input))
    }

    // ---------------------------------------------------------------------------------------------
    // Every IssueText caller keeps intra-word underscores (Task 2)
    // ---------------------------------------------------------------------------------------------

    /** The AI passive finding path (handleParsedAiIssues -> handleFinding) keeps `session_id`. */
    @Test
    fun aiPassiveFindingDetailKeepsIntraWordUnderscore() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.handleParsedAiIssues(
                listOf(
                    AiIssueItem(
                        title = "SQL Injection",
                        severity = "High",
                        detail = "The session_id parameter is reflected",
                        confidence = AI_FINDING_CONFIDENCE,
                    ),
                ),
                rig.csrfPost("issuetext-ai.example"),
                "LOW",
            )

            val detail = rig.built.single().detail
            assertTrue(detail.contains("session_id"), "the AI passive detail must keep session_id. Detail was: $detail")
        }
    }

    /** The BountyPrompt issue detail keeps `api_key`. */
    @Test
    fun bountyPromptDetailKeepsIntraWordUnderscore() {
        val detail =
            UiActions.buildIssueDetailHtml(
                bountyPromptDefinition(),
                BountyPromptFinding(
                    title = "finding",
                    detail = "Leaks the api_key value",
                    severity = "Medium",
                    confidence = BOUNTY_FINDING_CONFIDENCE,
                ),
            )
        assertTrue(detail.contains("api_key"), "the BountyPrompt detail must keep api_key. Detail was: $detail")
    }

    // ---------------------------------------------------------------------------------------------
    // The rest of the Markdown strip is unchanged (pins)
    // ---------------------------------------------------------------------------------------------

    @Test
    fun fencedCodeKeepsItsContent() {
        assertEquals("val a = 1", IssueText.sanitize("```kotlin\nval a = 1\n```"))
    }

    @Test
    fun backticksAreRemoved() {
        assertEquals("use code here", IssueText.sanitize("use `code` here"))
    }

    @Test
    fun markdownLinkBecomesTextAndUrl() {
        assertEquals("docs (https://x.example/a)", IssueText.sanitize("[docs](https://x.example/a)"))
    }

    @Test
    fun headingAndBlockquoteMarkersAreRemoved() {
        assertEquals("Title\nquoted", IssueText.sanitize("## Title\n> quoted"))
    }

    @Test
    fun lineEndingsAreNormalizedToLf() {
        assertEquals("a\nb\nc", IssueText.sanitize("a\r\nb\rc"))
    }

    @Test
    fun blankInputIsReturnedUnchanged() {
        assertEquals("   ", IssueText.sanitize("   "))
    }

    /** Leading and trailing underscores on an identifier are edge underscores and are removed, as before. */
    @Test
    fun edgeUnderscoresOnAnIdentifierAreRemoved() {
        assertEquals("csrf", IssueText.sanitize("_csrf"))
        assertEquals("init", IssueText.sanitize("__init__"))
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    /** Built the way IssueDetailHtmlEncodingTest.bountyPromptDefinition builds it. */
    private fun bountyPromptDefinition(): BountyPromptDefinition =
        BountyPromptDefinition(
            id = "p1",
            title = "T",
            category = BountyPromptCategory.DETECTION,
            outputType = BountyPromptOutputType.ISSUE,
            systemPrompt = "system",
            userPrompt = "user",
            severity = "Medium",
            confidence = BountyPromptConfidence.FIRM,
            tagsUsed = emptySet(),
        )

    /** The one place this class reaches a policy, so no test body names the policy factory. */
    private fun redactUnder(
        mode: PrivacyMode,
        text: String,
    ): String = Redaction.apply(text, RedactionPolicy.fromMode(mode), SALT)

    /** The agent created the issue with privacy OFF; the context mirrors IssueDetailHtmlEncodingTest. */
    private fun offContext(api: MontoyaApi): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
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

    private companion object {
        const val ATTRIBUTION_TEXT = "GET /api?page=1&access_token=sentineltokenattribution"
        const val SALT = "issuetext-salt"
        const val MCP_LIMIT = 4
        const val MCP_MAX_BODY_BYTES = 8192
        const val AI_FINDING_CONFIDENCE = 90
        const val BOUNTY_FINDING_CONFIDENCE = 70
    }
}
