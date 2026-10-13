package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.Serializable

// Input models of the native AI tools. Their handlers live in NativeTools.kt.

@Serializable
internal data class AiAnalyzeInput(
    val text: String,
    val jsonMode: Boolean = false,
    val maxOutputTokens: Int? = null,
)

@Serializable
internal data class AiPassiveScanInput(
    val proxyHistoryIndices: List<Int> = emptyList(),
    val siteMapUrl: String? = null,
    val maxRequests: Int = 10,
)

@Serializable
internal data class AiFindingsRecentInput(
    val n: Int = 10,
)

@Serializable
internal data class RedactPreviewInput(
    val text: String,
    val mode: String = "STRICT",
)

@Serializable
internal data class AiAuditQueryInput(
    val n: Int = 20,
)
