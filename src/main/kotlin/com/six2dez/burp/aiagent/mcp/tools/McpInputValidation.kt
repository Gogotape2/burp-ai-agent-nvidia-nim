package com.six2dez.burp.aiagent.mcp.tools

internal object McpInputValidation {
    private const val MAX_ITEMS = 1000
    private const val MAX_RANDOM_LENGTH = 65_536

    private const val MIN_TIMEOUT_MS = 1000L
    private const val MAX_TIMEOUT_MS = 600_000L

    fun validate(value: Any) {
        if (value is Paginated) {
            require(value.count in 1..MAX_ITEMS && value.offset >= 0) { "count must be 1-$MAX_ITEMS and offset non-negative" }
        }
        val hasNoTarget =
            when (value) {
                is StartAuditMode -> value.requests.isEmpty()
                is CreateAuditIssue -> value.httpRequest == null
                else -> false
            }
        if (value is HttpServiceParams && !hasNoTarget) validateService(value)
        validateOperation(value)
    }

    private fun validateOperation(value: Any) {
        when (value) {
            is SendHttp1Request -> require(value.timeoutMs in MIN_TIMEOUT_MS..MAX_TIMEOUT_MS) { "timeoutMs must be 1000-600000" }
            is SendHttp2Request -> require(value.timeoutMs in MIN_TIMEOUT_MS..MAX_TIMEOUT_MS) { "timeoutMs must be 1000-600000" }
            is GenerateRandomString -> require(value.length in 1..MAX_RANDOM_LENGTH && value.characterSet.isNotEmpty()) { "Provide length 1-$MAX_RANDOM_LENGTH and a non-empty characterSet" }
            is ProxyHistoryAnnotate -> require(value.limit in 1..MAX_ITEMS) { "limit must be 1-$MAX_ITEMS" }
            is AiPassiveScanInput -> require(value.maxRequests in 1..MAX_ITEMS && value.proxyHistoryIndices.all { it >= 0 }) { "maxRequests must be 1-$MAX_ITEMS; history indices must be non-negative" }
            is AiFindingsRecentInput -> require(value.n in 1..MAX_ITEMS) { "n must be 1-$MAX_ITEMS" }
            is AiAuditQueryInput -> require(value.n in 1..MAX_ITEMS) { "n must be 1-$MAX_ITEMS" }
            is ComparerSend -> require(value.items.size in 1..MAX_ITEMS) { "Provide 1-$MAX_ITEMS Comparer items" }
            is SetProjectOptions -> require(toolJson.parseToJsonElement(value.json) is kotlinx.serialization.json.JsonObject) { "Project options must be a JSON object" }
            is SetUserOptions -> require(toolJson.parseToJsonElement(value.json) is kotlinx.serialization.json.JsonObject) { "User options must be a JSON object" }
        }
    }
}
