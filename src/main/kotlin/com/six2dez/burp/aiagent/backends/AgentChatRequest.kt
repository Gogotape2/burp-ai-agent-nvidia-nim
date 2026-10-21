package com.six2dez.burp.aiagent.backends

import com.six2dez.burp.aiagent.redact.PrivacyMode

data class FunctionTool(
    val name: String,
    val description: String,
    val parametersJson: String,
)

data class FunctionCall(
    val id: String,
    val name: String,
    val argumentsJson: String,
)

data class FunctionResult(
    val callId: String,
    val content: String,
)

data class AgentTurnEvent(
    val stage: String,
    val detail: String,
    val call: FunctionCall? = null,
    val usage: TokenUsage? = null,
)

/** Optional structured chat path; existing backend and sendChat contracts remain available. */
data class AgentChatRequest(
    val chatSessionId: String,
    val backendId: String,
    val text: String,
    val history: List<ChatMessage>? = null,
    val contextJson: String? = null,
    val privacyMode: PrivacyMode = PrivacyMode.BALANCED,
    val determinismMode: Boolean = false,
    val traceId: String? = null,
    val systemPrompt: String? = null,
    val maxOutputTokens: Int? = null,
    val launchMetadata: Map<String, String>? = null,
    val tools: List<FunctionTool> = emptyList(),
    val previousToolResult: FunctionResult? = null,
    val jsonMode: Boolean = false,
)

interface ToolCallingConnection {
    fun sendAgentTurn(
        request: AgentChatRequest,
        onChunk: (String) -> Unit,
        onComplete: (Throwable?) -> Unit,
        onEvent: (AgentTurnEvent) -> Unit,
    )
}
