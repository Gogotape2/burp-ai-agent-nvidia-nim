package com.six2dez.burp.aiagent.supervisor

import com.six2dez.burp.aiagent.backends.AgentConnection

/** The tool owns this connection and must close it after completion or timeout. */
data class ToolAnalysisSession(
    val backendId: String,
    val connection: AgentConnection,
    val waitTimeoutMs: Long,
)
