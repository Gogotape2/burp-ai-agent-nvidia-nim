package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.util.IssueText
import com.six2dez.burp.aiagent.util.IssueUtils

// Phase 29 / BUILD-01, D-15: the core `issue_create` tool's support code, moved verbatim out of
// McpToolHelpers.kt (which moves to src/full with the generic tools in plan 29-11) so the store build
// compiles without the generic tool files. Same package and names; behavior unchanged.

@Suppress("ReturnCount") // moved verbatim from McpToolHelpers.kt; ADR-17 forbids re-adding its baseline entry
internal fun executeIssueCreate(
    input: CreateAuditIssue,
    api: MontoyaApi,
    context: McpToolContext,
): String {
    val severityEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
                .valueOf(input.severity.uppercase())
        } catch (_: Exception) {
            return "Invalid severity: ${input.severity}. Use: HIGH, MEDIUM, LOW, INFORMATION"
        }
    val confidenceEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
                .valueOf(input.confidence.uppercase())
        } catch (_: Exception) {
            return "Invalid confidence: ${input.confidence}. Use: CERTAIN, FIRM, TENTATIVE"
        }
    val typicalSeverityEnum =
        try {
            burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
                .valueOf((input.typicalSeverity ?: input.severity).uppercase())
        } catch (_: Exception) {
            severityEnum
        }

    val requestResponseList =
        if (input.httpRequest != null) {
            val service =
                input.toMontoyaServiceOrNull(context::resolveHost)
                    ?: return "Error: targetHostname/targetPort/usesHttps required when providing httpRequest"
            val fixedRequest = input.httpRequest.replace("\r", "").replace("\n", "\r\n")
            val request = HttpRequest.httpRequest(service, fixedRequest)
            val httpResponse =
                if (input.httpResponseContent != null) {
                    val fixedResponse = input.httpResponseContent.replace("\r", "").replace("\n", "\r\n")
                    burp.api.montoya.http.message.responses.HttpResponse
                        .httpResponse(fixedResponse)
                } else {
                    null
                }
            val rr =
                if (httpResponse != null) {
                    burp.api.montoya.http.message.HttpRequestResponse
                        .httpRequestResponse(request, httpResponse)
                } else {
                    burp.api.montoya.http.message.HttpRequestResponse
                        .httpRequestResponse(request, null)
                }
            listOf(rr)
        } else {
            findProxyHistoryMatch(api, input.baseUrl)
        }

    val issueNameWithPrefix = withAiIssuePrefix(input.name)
    if (hasEquivalentIssue(api, issueNameWithPrefix, input.baseUrl)) {
        return "Issue already exists: $issueNameWithPrefix"
    }
    val sanitizedDetail = IssueText.sanitize(input.detail)
    val sanitizedRemediation = IssueText.sanitize(input.remediation ?: "")
    val sanitizedBackground = IssueText.sanitize(input.background ?: "")
    val sanitizedRemediationBackground = IssueText.sanitize(input.remediationBackground ?: "")

    val issue =
        burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue(
            issueNameWithPrefix,
            sanitizedDetail,
            sanitizedRemediation,
            input.baseUrl,
            severityEnum,
            confidenceEnum,
            sanitizedBackground,
            sanitizedRemediationBackground,
            typicalSeverityEnum,
            requestResponseList,
        )

    api.siteMap().add(issue)
    return "Issue created: $issueNameWithPrefix (Severity: ${input.severity}, Confidence: ${input.confidence})"
}

internal fun findProxyHistoryMatch(
    api: MontoyaApi,
    baseUrl: String,
): List<burp.api.montoya.http.message.HttpRequestResponse> {
    return runCatching {
        val baseUri = java.net.URI(baseUrl)
        val baseScheme = baseUri.scheme?.lowercase()
        val baseHost = baseUri.host?.lowercase() ?: return@runCatching emptyList()
        val basePort = baseUri.port
        val basePath = baseUri.path.orEmpty()

        api
            .proxy()
            .history()
            .firstOrNull { entry ->
                val entryUrl = entry.request()?.url() ?: return@firstOrNull false
                val entryUri = runCatching { java.net.URI(entryUrl) }.getOrNull() ?: return@firstOrNull false
                entryUri.scheme?.lowercase() == baseScheme &&
                    entryUri.host?.lowercase() == baseHost &&
                    (basePort < 0 || entryUri.port == basePort) &&
                    entryUri.path.orEmpty().startsWith(basePath)
            }?.let { proxy ->
                listOf(
                    burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                        proxy.request(),
                        proxy.response(),
                    ),
                )
            } ?: emptyList()
    }.getOrDefault(emptyList())
}

@Suppress("ReturnCount") // moved verbatim from McpToolHelpers.kt; ADR-17 forbids re-adding its baseline entry
internal fun withAiIssuePrefix(rawName: String): String {
    val trimmed = rawName.trim()
    if (trimmed.startsWith("[AI]", ignoreCase = true)) return trimmed
    if (trimmed.startsWith("[AI Passive]", ignoreCase = true)) return trimmed
    return "[AI] $trimmed"
}

internal fun hasEquivalentIssue(
    api: MontoyaApi,
    name: String,
    baseUrl: String,
): Boolean =
    IssueUtils.hasEquivalentIssue(
        name = name,
        baseUrl = baseUrl,
        issues = api.siteMap().issues().map { issue -> issue.name() to issue.baseUrl() },
    )
