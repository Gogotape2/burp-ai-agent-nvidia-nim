package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.web.PublicWebHttp
import com.six2dez.burp.aiagent.web.WebFetchInput
import com.six2dez.burp.aiagent.web.WebResearchService
import com.six2dez.burp.aiagent.web.WebSearchInput
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrl

internal object WebResearchTools {
    private val hostInQuery = Regex("(?i)(?:https?://|\\b(?:[a-z0-9-]+\\.)+[a-z]{2,63}\\b|\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b|[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:]+)")
    private val anonymizedHost = Regex("(?i)host-[a-f0-9]{12}\\.local")

    fun schema(name: String): io.modelcontextprotocol.kotlin.sdk.Tool.Input =
        when (name) {
            "web_search" -> WebSearchInput::class.asInputSchema()
            "web_fetch" -> WebFetchInput::class.asInputSchema()
            else ->
                io.modelcontextprotocol.kotlin.sdk.Tool
                    .Input()
        }

    private val json = Json { ignoreUnknownKeys = false }
    private var transport: PublicWebHttp? = null
    private var service: WebResearchService? = null

    @Synchronized
    private fun defaultService(): WebResearchService =
        service ?: PublicWebHttp().let { http ->
            transport = http
            WebResearchService(http).also { service = it }
        }

    fun execute(
        name: String,
        args: String?,
        context: McpToolContext,
    ): String =
        com.six2dez.burp.aiagent.web.WebCancellation.within(context.webCancelled) {
            val client = context.webResearchClient ?: defaultService()
            val result =
                when (name) {
                    "web_search" -> {
                        val input = json.decodeFromString<WebSearchInput>(args.orEmpty())
                        require(input.query.length in 2..com.six2dez.burp.aiagent.web.WebLimits.MAX_QUERY_CHARS && input.query.none { it.isISOControl() }) { "Search requires a short single-line product/version/CVE query" }
                        require(!anonymizedHost.containsMatchIn(input.query)) { "Use product/version terms instead of anonymized target names" }
                        require(context.privacyMode != com.six2dez.burp.aiagent.redact.PrivacyMode.STRICT || !hostInQuery.containsMatchIn(input.query)) { "Strict privacy permits product/version/CVE searches without domains, URLs or IP addresses" }
                        require(
                            context.redactIfNeeded(input.query) == input.query && clean(input.query, context) == input.query,
                        ) { "Search query contains protected data. Use product/version/CVE terms without target traffic, credentials or anonymized hosts." }
                        client.search(input)
                    }
                    "web_fetch" -> {
                        val input = json.decodeFromString<WebFetchInput>(args.orEmpty())
                        require(input.url.length <= com.six2dez.burp.aiagent.web.WebLimits.MAX_URL_CHARS) { "Web URL is too long" }
                        val url = input.url.toHttpUrl()
                        val resolved =
                            url
                                .newBuilder()
                                .host(context.resolveHost(url.host))
                                .build()
                                .toString()
                        require(clean(resolved, context) == resolved) { "Web URL contains protected data; use a public documentation link without credentials" }
                        client.fetch(input.copy(url = resolved))
                    }
                    else -> error("Unknown web tool")
                }
            context.redactIfNeeded(clean(result, context))
        }

    private fun clean(
        value: String,
        context: McpToolContext,
    ): String = Redaction.apply(value, RedactionPolicy(stripCookies = true, redactTokens = true, anonymizeHosts = false), stableHostSalt = context.hostSalt)

    @Synchronized
    fun shutdown() {
        transport?.close()
        transport = null
        service = null
        com.six2dez.burp.aiagent.web.WebDnsResolver
            .shutdown()
    }
}
