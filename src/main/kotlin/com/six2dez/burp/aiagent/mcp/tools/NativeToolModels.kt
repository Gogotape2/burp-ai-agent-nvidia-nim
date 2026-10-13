package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.http.HttpService
import kotlinx.serialization.Serializable

// Phase 29 / BUILD-01, D-15: the McpToolModels.kt types the core still uses (the executor's ToolSpec,
// and issue_create's input with its HttpServiceParams supertype), moved verbatim so McpToolModels.kt
// can move to src/full with the generic tools in plan 29-11. Same package and names.

// ──────────────────────────────────────────────────────────────────────────────
// Shared interfaces
// ──────────────────────────────────────────────────────────────────────────────

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(resolveHost: (String) -> String = { it }): HttpService = HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)

    fun toMontoyaServiceOrNull(resolveHost: (String) -> String = { it }): HttpService? {
        if (targetHostname.isBlank() || targetPort <= 0) return null
        return HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ToolSpec (used by McpToolExecutor.describeTools)
// ──────────────────────────────────────────────────────────────────────────────

data class ToolSpec(
    val id: String,
    val description: String,
    val enabled: Boolean,
    val unsafeOnly: Boolean,
    val proOnly: Boolean,
    val argsSchema: String?,
)

// ──────────────────────────────────────────────────────────────────────────────
// issue_create input (native tool)
// ──────────────────────────────────────────────────────────────────────────────

@Serializable
data class CreateAuditIssue(
    val name: String,
    val detail: String,
    val baseUrl: String,
    val severity: String,
    val confidence: String,
    val remediation: String? = null,
    val background: String? = null,
    val remediationBackground: String? = null,
    val typicalSeverity: String? = null,
    val httpRequest: String? = null,
    val httpResponseContent: String? = null,
    override val targetHostname: String = "",
    override val targetPort: Int = 443,
    override val usesHttps: Boolean = true,
) : HttpServiceParams {
    override fun toMontoyaServiceOrNull(resolveHost: (String) -> String): HttpService? =
        if (targetHostname.isNotBlank()) {
            HttpService.httpService(resolveHost(targetHostname), targetPort, usesHttps)
        } else {
            null
        }
}
