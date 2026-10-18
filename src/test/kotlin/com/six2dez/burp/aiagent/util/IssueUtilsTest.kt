package com.six2dez.burp.aiagent.util

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IssueUtilsTest {
    @Test
    fun canonicalIssueName_stripsAiPrefixesAndNormalizesCase() {
        assertEquals("sql injection", IssueUtils.canonicalIssueName("[AI] SQL Injection"))
        assertEquals("sql injection", IssueUtils.canonicalIssueName("[AI Passive] sql injection"))
        assertEquals("idor", IssueUtils.canonicalIssueName("  [ai] IDOR  "))
    }

    @Test
    fun hasEquivalentIssue_matchesCanonicalNameOnSameBaseUrl() {
        val issues =
            listOf(
                "[AI Passive] SQL Injection" to "https://example.test/path",
                "Other issue" to "https://example.test/other",
            )

        assertTrue(IssueUtils.hasEquivalentIssue("[AI] sql injection", "https://example.test/path", issues))
        assertFalse(IssueUtils.hasEquivalentIssue("[AI] sql injection", "https://example.test/other", issues))
    }

    @Test
    fun formatIssueDetailHtml_escapesHtmlAndPreservesIndentedPrefix() {
        val html = IssueUtils.formatIssueDetailHtml(listOf("line<1>", "  indented & value"))
        assertTrue(html.contains("line&lt;1&gt;"))
        assertTrue(html.contains("&nbsp;&nbsp;indented &amp; value"))
    }

    /** 32-REVIEW CR-01: the read-path decode is the exact inverse of the stored-form escaping. */
    @Test
    fun issueDetailHtmlToText_isTheExactInverseOfFormatIssueDetailHtml() {
        val cases =
            listOf(
                listOf("<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"),
                listOf("already escaped &lt;b&gt; stays literal"),
                listOf("the literal text x<br>y is not a line break"),
                listOf("a bare a&b", "a literal &nbsp; entity", "&amp;amp; twice"),
                listOf("  two-space indent", "    four-space indent", " one space"),
                listOf("before", "", "after"),
                listOf(""),
                emptyList(),
                listOf("GET /api?page=1&access_token=value", "X-Api-Key: value", "Cookie: sid=value"),
            )

        for (lines in cases) {
            assertEquals(
                lines.joinToString("\n"),
                IssueUtils.issueDetailHtmlToText(IssueUtils.formatIssueDetailHtml(lines)),
                "round trip broke for $lines",
            )
        }
    }

    @Test
    fun issueDetailHtmlToText_appliesOnlyTheFiveSubstitutionsToBurpNativeHtml() {
        assertEquals("<p>a & b</p>", IssueUtils.issueDetailHtmlToText("<p>a &amp; b</p>"))
        assertEquals("<b>x</b>\ny &quot;z&quot;", IssueUtils.issueDetailHtmlToText("<b>x</b><br>y &quot;z&quot;"))
        assertEquals("", IssueUtils.issueDetailHtmlToText(""))
    }
}
