package com.six2dez.burp.aiagent.scanner

data class PassiveAiFinding(
    val timestamp: Long,
    val url: String,
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
    val source: String = "ai",
    val issueCreated: Boolean = true,
)

data class PassiveAiScannerStatus(
    val enabled: Boolean,
    val requestsAnalyzed: Int,
    val issuesFound: Int,
    val lastAnalysisTime: Long,
    val queueSize: Int,
    /** Phase 31 / D-02: the scanner is on but the AI access policy refuses its saved backend. */
    val aiGatePaused: Boolean = false,
)

/**
 * Phase 31 gap closure WR-04 / D-01: what a manual passive scan request led to, so the caller that
 * shows it to a user can tell a refusal apart from a scan that queued nothing.
 */
sealed interface ManualPassiveScanStart {
    /** The scan was accepted and [count] requests were queued (0 for an empty selection or a budget pause). */
    data class Queued(
        val count: Int,
    ) : ManualPassiveScanStart

    /** The AI access policy refused the saved backend; [reason] is the policy's refusal text, verbatim. */
    data class Refused(
        val reason: String,
    ) : ManualPassiveScanStart
}

internal data class LocalFinding(
    val title: String,
    val severity: String,
    val detail: String,
    val confidence: Int,
)

internal data class AiIssueItem(
    val reasoning: String? = null,
    val title: String? = null,
    val severity: String? = null,
    val detail: String? = null,
    val confidence: Int? = null,
    val requestIndex: Int? = null,
)

internal data class CachedAiIssues(
    val createdAtMs: Long,
    val issues: List<AiIssueItem>,
)
