package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.scanner.AuditConfiguration
import com.six2dez.burp.aiagent.mcp.McpToolContext

internal object McpScannerTools {
    private const val MAX_SCAN_REQUESTS = 1000

    // Delete a task if any Montoya addRequest operation fails after startAudit.
    @Suppress("TooGenericExceptionCaught")
    fun startAudit(
        mode: String,
        inputs: List<String>,
        target: HttpServiceParams?,
        context: McpToolContext,
    ): String {
        require(inputs.size <= MAX_SCAN_REQUESTS) { "At most $MAX_SCAN_REQUESTS requests per audit" }
        if (inputs.isNotEmpty()) require(target != null) { "Target hostname/port required when providing requests" }
        val requests =
            inputs.map { raw ->
                val service = checkNotNull(target)
                validateService(service)
                require(raw.isNotBlank()) { "Audit request must not be empty" }
                val fixed = normalizeHttpRequest(raw)
                val url = McpScopeFilter.deriveScopeUrl(context.resolveHost(service.targetHostname), service.targetPort, service.usesHttps, fixed)
                McpScopeFilter.rejectIfOutOfScope(url, context)?.let { throw IllegalArgumentException(it) }
                McpTextMessages.request(service.toMontoyaService(context::resolveHost), fixed)
            }
        val config = AuditConfiguration.auditConfiguration(resolveAuditConfig(mode))
        val audit = context.api.scanner().startAudit(config)
        try {
            requests.forEach { audit.addRequest(it) }
            val id = ScannerTaskRegistry.put(audit)
            return "Started audit${if (requests.isEmpty()) "" else " with requests"}: id=$id status=${audit.statusMessage()} queued_requests=${requests.size}"
        } catch (e: Exception) {
            runCatching { audit.delete() }
            throw e
        }
    }

    fun validateCrawl(
        urls: List<String>,
        context: McpToolContext,
    ) {
        require(urls.isNotEmpty() && urls.size <= MAX_SCAN_REQUESTS) { "Provide 1-$MAX_SCAN_REQUESTS crawl seed URLs" }
        urls.forEach { url ->
            val uri = java.net.URI(url)
            require(uri.scheme in setOf("http", "https") && uri.host != null) { "Crawl seeds must be absolute HTTP(S) URLs" }
            McpScopeFilter.rejectIfOutOfScope(url, context)?.let { throw IllegalArgumentException(it) }
        }
    }
}

private const val MAX_TCP_PORT = 65535

internal fun validateService(service: HttpServiceParams) {
    require(service.targetPort in 1..MAX_TCP_PORT) { "targetPort must be between 1 and 65535" }
    require(service.targetHostname.isNotBlank() && service.targetHostname.none { it.isWhitespace() || it in "/\\?#@" }) { "targetHostname must contain a host without a URL scheme or path" }
}
