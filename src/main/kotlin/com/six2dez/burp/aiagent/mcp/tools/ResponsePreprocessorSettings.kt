package com.six2dez.burp.aiagent.mcp.tools

// Phase 29 / BUILD-01, D-15: the preprocessing settings the core passes through McpSupervisor,
// McpToolContext and AgentSettings, moved verbatim out of ResponsePreprocessor.kt (which moves to
// src/full with the generic tools in plan 29-11). Same package and name.

data class ResponsePreprocessorSettings(
    val preprocessProxyHistory: Boolean = true,
    val preprocessMaxResponseSizeKb: Int = 20,
    val preprocessFilterBinaryContent: Boolean = true,
    val preprocessAllowedContentTypes: Set<String> =
        setOf(
            "text/",
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ),
)
