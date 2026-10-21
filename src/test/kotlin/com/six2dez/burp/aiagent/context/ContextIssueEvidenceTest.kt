package com.six2dez.burp.aiagent.context

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class ContextIssueEvidenceTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun issueSnapshotIncludesBoundedHttpEvidenceWithTheSelectedPrivacyPolicy() {
        val issue = issue(listOf(evidence()))
        val capture = ContextCollector(mock<MontoyaApi>()).fromAuditIssues(listOf(issue), ContextOptions(PrivacyMode.STRICT, true, "evidence-salt", maxRequestBodyChars = 80, maxResponseBodyChars = 80))
        val items = mapper.readTree(capture.contextJson).path("items")
        assertEquals(2, items.size())
        assertEquals("Selected finding", items.path(0).path("name").asText())
        val http = items.path(1)
        assertEquals("issue_evidence", http.path("tool").asText())
        assertTrue(http.path("request").asText().contains("body truncated"))
        assertTrue(http.path("response").asText().contains("body truncated"))
        assertTrue(http.path("request").asText().length < 1000)
        for (secret in listOf("private.fixture.test", "header-fixture-secret", "cookie-fixture-secret", "query-fixture-secret", "detail-fixture-secret")) {
            assertFalse(capture.contextJson.contains(secret), "Captured issue evidence must not expose $secret")
        }
        assertTrue(http.path("url").asText().contains("host-"))
    }

    @Test
    fun balancedHttpCaptureRedactsUrlQuerySecretsWhileKeepingTheHost() {
        val capture = ContextCollector(mock<MontoyaApi>()).fromRequestResponses(listOf(evidence()), ContextOptions(PrivacyMode.BALANCED, false, "salt"))
        val url =
            mapper
                .readTree(capture.contextJson)
                .path("items")
                .path(0)
                .path("url")
                .asText()
        assertTrue(url.contains("private.fixture.test"))
        assertFalse(url.contains("query-fixture-secret"))
    }

    @Test
    fun issueEvidenceCaptureHasAnExplicitTwentyItemBound() {
        val capture = ContextCollector(mock<MontoyaApi>()).fromAuditIssues(listOf(issue((0 until 30).map { evidence(it) })), ContextOptions(PrivacyMode.BALANCED, false, "salt"))
        val items = mapper.readTree(capture.contextJson).path("items")
        assertEquals(20, items.count { it.path("tool").asText() == "issue_evidence" })
    }

    private fun issue(evidence: List<HttpRequestResponse>): AuditIssue {
        val issue = mock<AuditIssue>()
        val service = mock<HttpService>()
        whenever(service.host()).thenReturn("private.fixture.test")
        whenever(issue.httpService()).thenReturn(service)
        whenever(issue.name()).thenReturn("Selected finding")
        whenever(issue.severity()).thenReturn(AuditIssueSeverity.HIGH)
        whenever(issue.confidence()).thenReturn(AuditIssueConfidence.FIRM)
        whenever(issue.detail()).thenReturn("Authorization: Bearer detail-fixture-secret")
        whenever(issue.remediation()).thenReturn("Review the captured evidence")
        whenever(issue.requestResponses()).thenReturn(evidence)
        return issue
    }

    private fun evidence(index: Int = 0): HttpRequestResponse {
        val request = mock<HttpRequest>()
        val response = mock<HttpResponse>()
        val pair = mock<HttpRequestResponse>()
        whenever(request.url()).thenReturn("https://private.fixture.test/item/$index?token=query-fixture-secret")
        whenever(request.method()).thenReturn("GET")
        whenever(request.toString()).thenReturn("GET /item/$index?token=query-fixture-secret HTTP/1.1\r\nHost: private.fixture.test\r\nAuthorization: Bearer header-fixture-secret\r\n\r\n" + "a".repeat(500))
        whenever(response.toString()).thenReturn("HTTP/1.1 200 OK\r\nSet-Cookie: sid=cookie-fixture-secret\r\n\r\n" + "b".repeat(500))
        whenever(pair.request()).thenReturn(request)
        whenever(pair.response()).thenReturn(response)
        return pair
    }
}
