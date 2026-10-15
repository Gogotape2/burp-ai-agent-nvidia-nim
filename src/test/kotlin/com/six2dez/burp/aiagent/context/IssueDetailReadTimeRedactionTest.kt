package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpService
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import com.fasterxml.jackson.databind.ObjectMapper
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.tools.CreateAuditIssue
import com.six2dez.burp.aiagent.mcp.tools.executeIssueCreate
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.FiledIssue
import com.six2dez.burp.aiagent.scanner.PassiveScanCheckRig
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * The issue_create round trip shared by the core and the full-build CR-01 regression tests.
 *
 * An agent files an issue through issue_create with privacy OFF, so the secrets reach Burp's
 * stored issue as escaped, `<br>`-joined HTML (D-10, D-12). The read paths that send issue text
 * to the AI backend or to an MCP client must still redact them under STRICT and BALANCED
 * (32-REVIEW CR-01). Every value avoids `_`, `*` and backticks, so IssueText.sanitize keeps it.
 *
 * The sentinel literals follow the survival sweep's `"sentinel[A-Za-z0-9]*"` vocabulary, so a
 * presence assertion on one of them under a redacting mode would be flagged.
 */
internal object IssueRoundTripFixture {
    const val BENIGN = "benign control line stays"

    const val TOKEN = "sentineltokencharlie"
    const val API_KEY = "sentinelapikeyalpha"
    const val COOKIE = "sentinelcookiebravo"
    const val REMEDIATION_TOKEN = "sentinelremediationdelta"
    const val BACKGROUND_API_KEY = "sentinelbackgroundecho"
    const val REMEDIATION_BACKGROUND_COOKIE = "sentinelremediationbgfoxtrot"

    // The benign line comes BEFORE the token line: on the JSON path the token rule's value class
    // does not stop at a JSON-escaped newline, so it also consumes the start of the next line.
    val DETAIL_LINES =
        listOf(
            "Observed request:",
            BENIGN,
            "GET /api?page=1&access_token=$TOKEN",
            "X-Api-Key: $API_KEY",
            "Cookie: sid=$COOKIE",
        )
    val REMEDIATION_LINES =
        listOf(
            "Rotate the key.",
            "Callback seen: /cb?state=1&access_token=$REMEDIATION_TOKEN",
        )
    val BACKGROUND_LINES = listOf("Seen as", "X-Api-Key: $BACKGROUND_API_KEY")
    val REMEDIATION_BACKGROUND_LINES = listOf("Seen as", "Cookie: sid=$REMEDIATION_BACKGROUND_COOKIE")

    val CORE_SENTINELS = listOf(TOKEN, API_KEY, COOKIE, REMEDIATION_TOKEN)
    val FULL_SENTINELS = CORE_SENTINELS + listOf(BACKGROUND_API_KEY, REMEDIATION_BACKGROUND_COOKIE)

    /** Files the fixture through the real issue_create path (privacy OFF) and returns what Burp stored. */
    fun fileThroughIssueCreate(): FiledIssue =
        PassiveScanCheckRig().use { rig ->
            val result =
                executeIssueCreate(
                    CreateAuditIssue(
                        name = "Token in issue text",
                        detail = DETAIL_LINES.joinToString("\n"),
                        baseUrl = "https://issue-roundtrip.example/api",
                        severity = "MEDIUM",
                        confidence = "FIRM",
                        remediation = REMEDIATION_LINES.joinToString("\n"),
                        background = BACKGROUND_LINES.joinToString("\n"),
                        remediationBackground = REMEDIATION_BACKGROUND_LINES.joinToString("\n"),
                    ),
                    rig.api,
                    creationContext(rig.api),
                )
            check(result.startsWith("Issue created: ")) { "issue_create failed: $result. Errors: ${rig.errors}" }
            rig.built.single()
        }

    /**
     * A full AuditIssue mock carrying what Burp stored for [filed]. The rig's own mock stubs only a
     * few getters, so the read paths need this one. Nested mocks are built before the issue's
     * `whenever` chain (UnfinishedStubbing otherwise).
     */
    fun asAuditIssue(
        filed: FiledIssue,
        host: String,
    ): AuditIssue {
        val service = mock<HttpService>()
        whenever(service.host()).thenReturn(host)
        whenever(service.port()).thenReturn(443)
        whenever(service.secure()).thenReturn(true)

        val definition = mock<AuditIssueDefinition>()
        whenever(definition.name()).thenReturn("issue-roundtrip")
        whenever(definition.background()).thenReturn(filed.background)
        whenever(definition.remediation()).thenReturn(filed.remediationBackground)
        whenever(definition.typeIndex()).thenReturn(0)

        val issue = mock<AuditIssue>()
        whenever(issue.name()).thenReturn(filed.name)
        whenever(issue.detail()).thenReturn(filed.detail)
        whenever(issue.remediation()).thenReturn(filed.remediation)
        whenever(issue.baseUrl()).thenReturn("https://$host/api")
        whenever(issue.severity()).thenReturn(filed.severity)
        whenever(issue.confidence()).thenReturn(filed.confidence)
        whenever(issue.httpService()).thenReturn(service)
        whenever(issue.requestResponses()).thenReturn(emptyList())
        whenever(issue.collaboratorInteractions()).thenReturn(emptyList())
        whenever(issue.definition()).thenReturn(definition)
        return issue
    }

    private fun creationContext(api: MontoyaApi): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = PrivacyMode.OFF,
            determinismMode = false,
            hostSalt = "roundtrip-create-salt",
            toolToggles = emptyMap(),
            unsafeEnabled = false,
            unsafeTools = emptySet(),
            enabledUnsafeTools = emptySet(),
            limiter = McpRequestLimiter(CREATION_LIMIT),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = CREATION_MAX_BODY_BYTES,
        )

    private const val CREATION_LIMIT = 4
    private const val CREATION_MAX_BODY_BYTES = 65_536
}

/**
 * 32-REVIEW CR-01 (core, both builds): the extension stores issue text as escaped, `<br>`-joined
 * HTML. `&amp;` hides the `[?&]` anchor of the query and form token rules, and `<br>` hides the
 * line starts the header rules need. [ContextCollector.fromAuditIssues] decodes detail and
 * remediation before redaction, so a secret an agent wrote into issue_create does not reach the
 * AI backend under STRICT or BALANCED.
 *
 * Survival-sweep discipline: presence assertions on sentinels live only in the OFF-only function;
 * the redacting-mode function asserts absence and the exact redacted shapes.
 */
class IssueDetailReadTimeRedactionTest {
    private val mapper = ObjectMapper()

    @Test
    fun issueCreateStoresTheFixtureEscaped() {
        val filed = IssueRoundTripFixture.fileThroughIssueCreate()

        assertTrue(filed.detail.contains("&amp;access_token="), filed.detail)
        assertTrue(filed.detail.contains("<br>"), filed.detail)
        assertFalse(filed.detail.contains("\n"), filed.detail)
    }

    @Test
    fun offCaptureCarriesEveryCoreValue() {
        val filed = IssueRoundTripFixture.fileThroughIssueCreate()
        val capture =
            ContextCollector(mock<MontoyaApi>()).fromAuditIssues(
                listOf(IssueRoundTripFixture.asAuditIssue(filed, CONTEXT_HOST)),
                ContextOptions(privacyMode = PrivacyMode.OFF, deterministic = true, hostSalt = SALT),
            )

        for (sentinel in IssueRoundTripFixture.CORE_SENTINELS) {
            assertTrue(capture.contextJson.contains(sentinel), "OFF must keep $sentinel: ${capture.contextJson}")
        }
    }

    @Test
    fun redactingCaptureHidesEveryCoreValue() {
        val filed = IssueRoundTripFixture.fileThroughIssueCreate()

        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val capture =
                ContextCollector(mock<MontoyaApi>()).fromAuditIssues(
                    listOf(IssueRoundTripFixture.asAuditIssue(filed, CONTEXT_HOST)),
                    ContextOptions(privacyMode = mode, deterministic = true, hostSalt = SALT),
                )

            for (sentinel in IssueRoundTripFixture.CORE_SENTINELS) {
                assertFalse(capture.contextJson.contains(sentinel), "$mode leaked $sentinel: ${capture.contextJson}")
                assertFalse(capture.previewText.contains(sentinel), "$mode leaked $sentinel: ${capture.previewText}")
            }

            val item = mapper.readTree(capture.contextJson)["items"][0]
            val detail = item["detail"].asText()
            val remediation = item["remediation"].asText()
            assertTrue(detail.contains("access_token=[REDACTED]"), "$mode detail: $detail")
            assertTrue(detail.contains("X-Api-Key: [REDACTED]"), "$mode detail: $detail")
            assertTrue(detail.contains("Cookie: [STRIPPED]"), "$mode detail: $detail")
            assertTrue(detail.contains(IssueRoundTripFixture.BENIGN), "$mode detail: $detail")
            assertTrue(remediation.contains("access_token=[REDACTED]"), "$mode remediation: $remediation")
        }
    }

    private companion object {
        const val SALT = "issue-roundtrip-salt"
        const val CONTEXT_HOST = "context-roundtrip.example"
    }
}
