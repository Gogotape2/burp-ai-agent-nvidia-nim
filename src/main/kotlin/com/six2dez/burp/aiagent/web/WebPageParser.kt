package com.six2dez.burp.aiagent.web

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.jsoup.Jsoup

internal object WebPageParser {
    fun search(resource: WebResource): List<Map<String, String>> {
        val doc = Jsoup.parse(resource.body, resource.url)
        check(doc.select("form[action*=anomaly], #challenge-form, .anomaly-modal").isEmpty()) { "Search provider returned a CAPTCHA; try later. No automatic retry." }
        val results =
            doc
                .select("a.result-link, a.result__a")
                .mapNotNull { element ->
                    val href = element.absUrl("href").toHttpUrlOrNull() ?: return@mapNotNull null
                    val destination = href.queryParameter("uddg") ?: href.toString()
                    val url = runCatching { PublicWebAddress.parse(destination) }.getOrNull() ?: return@mapNotNull null
                    val title = element.text().trim().take(WebLimits.MAX_TITLE_CHARS)
                    if (title.isBlank() || url.host.endsWith("duckduckgo.com")) null else mapOf("title" to title, "url" to url.toString())
                }.distinctBy { it["url"] }
                .take(WebLimits.MAX_RESULTS)
        check(results.isNotEmpty() || doc.text().contains("No results found", ignoreCase = true)) { "Search returned no recognizable results; the provider may be unavailable or its HTML changed" }
        return results
    }

    fun page(resource: WebResource): Pair<String, String> {
        if (!resource.mediaType.contains("html")) return resource.url to resource.body
        val doc = Jsoup.parse(resource.body, resource.url)
        doc.select("script,style,noscript,nav,header,footer,form,svg,iframe").remove()
        val body =
            doc
                .body()
                .wholeText()
                .lineSequence()
                .map { it.trim().replace(Regex("[\\t ]+"), " ") }
                .filter { it.isNotBlank() }
                .joinToString("\n")
        check(body.isNotBlank()) { "Page contains no readable text; JavaScript-only and login pages are not supported" }
        return doc.title().take(WebLimits.MAX_TITLE_CHARS).ifBlank { resource.url } to body
    }
}
