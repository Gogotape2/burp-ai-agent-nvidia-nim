package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.context.IssueRoundTripFixture
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * 32-REVIEW CR-01 (full build): an issue an agent filed through issue_create with privacy OFF is
 * stored as escaped, `<br>`-joined HTML. Read back through the real `scanner_issues` tool
 * (McpToolExecutor -> handler -> toSerializableForm -> redactIfNeeded), none of its secrets may
 * reach the MCP client under STRICT or BALANCED. `toSerializableForm` decodes the issue text so the
 * query/form token rules and the line-start header rules match again.
 *
 * Exact redacted text is not pinned: on the JSON path the token rule's value class does not stop at
 * a JSON-escaped newline, so it also consumes the start of the next line. That over-match predates
 * Phase 32, leaks nothing and is deferred.
 *
 * Survival-sweep discipline: sentinel presence is asserted only in the OFF-only function.
 */
class ScannerIssuesReadTimeRedactionTest {
    @Test
    fun offScannerIssuesCarriesEveryValue() {
        val result = scannerIssues(PrivacyMode.OFF)

        for (sentinel in IssueRoundTripFixture.FULL_SENTINELS) {
            assertTrue(result.contains(sentinel), "OFF must keep $sentinel: $result")
        }
        assertTrue(result.contains(IssueRoundTripFixture.BENIGN), result)
    }

    @Test
    fun redactingScannerIssuesHidesEveryValue() {
        for (mode in listOf(PrivacyMode.STRICT, PrivacyMode.BALANCED)) {
            val result = scannerIssues(mode)

            assertFalse(result.startsWith("Error"), "$mode: $result")
            for (sentinel in IssueRoundTripFixture.FULL_SENTINELS) {
                assertFalse(result.contains(sentinel), "$mode leaked $sentinel: $result")
            }
            assertTrue(result.contains(IssueRoundTripFixture.BENIGN), "$mode dropped the benign line: $result")
        }
    }

    private fun scannerIssues(mode: PrivacyMode): String {
        val filed = IssueRoundTripFixture.fileThroughIssueCreate()
        val issue = IssueRoundTripFixture.asAuditIssue(filed, HOST)
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        whenever(api.siteMap().issues()).thenReturn(listOf(issue))

        return McpToolExecutor.executeTool(
            "scanner_issues",
            "{\"count\":10,\"offset\":0}",
            contextWith(api, mode),
            ToolCallOrigin.UserSlashCommand,
        )
    }

    private fun contextWith(
        api: MontoyaApi,
        mode: PrivacyMode,
    ): McpToolContext =
        McpToolContext(
            api = api,
            privacyMode = mode,
            determinismMode = false,
            hostSalt = "scanner-roundtrip-salt",
            toolToggles = McpToolCatalog.all().associate { it.id to true },
            unsafeEnabled = true,
            unsafeTools = McpToolCatalog.unsafeToolIds(),
            enabledUnsafeTools = McpToolCatalog.unsafeToolIds(),
            limiter = McpRequestLimiter(LIMIT),
            edition = BurpSuiteEdition.PROFESSIONAL,
            maxBodyBytes = MAX_BODY_BYTES,
        )

    private companion object {
        const val HOST = "scanner-roundtrip.example"
        const val LIMIT = 8
        const val MAX_BODY_BYTES = 65_536
    }
}
