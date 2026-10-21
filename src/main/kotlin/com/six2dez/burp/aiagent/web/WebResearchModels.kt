package com.six2dez.burp.aiagent.web

import kotlinx.serialization.Serializable

internal object WebLimits {
    const val TIMEOUT_SECONDS = 20L
    const val CONNECT_SECONDS = 8L
    const val MAX_BYTES = 1024 * 1024
    const val MAX_QUERY_CHARS = 512
    const val MAX_URL_CHARS = 2048
    const val MAX_RESULTS = 10
    const val MAX_TEXT_CHARS = 24_000
    const val DEFAULT_TEXT_CHARS = 12_000
    const val MAX_REDIRECTS = 4
    const val CACHE_ENTRIES = 12
    const val CACHE_TTL_MS = 300_000L
    const val SEARCH_INTERVAL_MS = 1500L
    const val SEARCH_ENDPOINT = "https://lite.duckduckgo.com/lite/"
    const val USER_AGENT = "Mozilla/5.0 (compatible; Burp-AI-Agent-WebResearch/1.0)"
    const val MAX_TITLE_CHARS = 300
    const val MAX_PAGE_QUERY_CHARS = 256
    const val MATCH_LEADING_CHARS = 300
    const val CACHE_LOAD_FACTOR = 0.75f
    const val READ_CHUNK_BYTES = 8192L
    const val ACCEPTED_ASYNC_STATUS = 202
    const val HTTP_PORT = 80
    const val HTTPS_PORT = 443
    private const val MOVED_PERMANENTLY = 301
    private const val FOUND = 302
    private const val SEE_OTHER = 303
    private const val TEMPORARY_REDIRECT = 307
    private const val PERMANENT_REDIRECT = 308
    val REDIRECT_STATUSES = setOf(MOVED_PERMANENTLY, FOUND, SEE_OTHER, TEMPORARY_REDIRECT, PERMANENT_REDIRECT)
}

@Serializable
data class WebSearchInput(
    val query: String,
    val count: Int = 5,
)

@Serializable
data class WebFetchInput(
    val url: String,
    val offset: Int = 0,
    val maxChars: Int = WebLimits.DEFAULT_TEXT_CHARS,
    val query: String? = null,
)

data class WebResource(
    val url: String,
    val mediaType: String,
    val body: String,
    val retrievedAt: String,
)

fun interface WebTransport {
    fun get(url: String): WebResource
}

interface WebResearchClient {
    fun search(input: WebSearchInput): String

    fun fetch(input: WebFetchInput): String
}
