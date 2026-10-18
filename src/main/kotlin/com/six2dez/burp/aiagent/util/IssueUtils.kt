package com.six2dez.burp.aiagent.util

import java.net.URI

object IssueUtils {
    private val aiPrefixRegex = Regex("^(?:\\[AI(?:[^\\]]*)?\\]\\s*)+", RegexOption.IGNORE_CASE)

    private val numericIdRegex = Regex("^\\d{2,}$")
    private val uuidLikeRegex = Regex("^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$", RegexOption.IGNORE_CASE)
    private val objectIdLikeRegex = Regex("^[a-f0-9]{24}$", RegexOption.IGNORE_CASE)

    fun canonicalIssueName(name: String): String =
        name
            .trim()
            .replace(aiPrefixRegex, "")
            .trim()
            .lowercase()

    /**
     * Normalize a URL for dedup comparison:
     * - Strip query string
     * - Replace numeric IDs, UUIDs, and ObjectIDs in path segments with placeholders
     */
    fun normalizeUrl(url: String): String {
        if (url.isBlank()) return url
        return try {
            val uri = URI(url)
            val normalizedPath = normalizePathSegments(uri.path.orEmpty())
            URI(uri.scheme, uri.authority, normalizedPath, null, null).toString()
        } catch (_: Exception) {
            // Fallback: strip query string
            url.substringBefore('?')
        }
    }

    fun normalizePathSegments(path: String): String {
        if (path.isBlank()) return "/"
        return path
            .split('/')
            .joinToString("/") { segment ->
                when {
                    segment.isBlank() -> ""
                    numericIdRegex.matches(segment) -> "{id}"
                    uuidLikeRegex.matches(segment) -> "{uuid}"
                    objectIdLikeRegex.matches(segment) -> "{oid}"
                    else -> segment
                }
            }.ifBlank { "/" }
    }

    fun formatIssueDetailHtml(lines: List<String>): String =
        lines.joinToString("<br>") { line ->
            val escaped =
                line
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
            if (escaped.startsWith("  ")) {
                "&nbsp;&nbsp;" + escaped.drop(2)
            } else {
                escaped
            }
        }

    /**
     * The exact inverse of [formatIssueDetailHtml]: `issueDetailHtmlToText(formatIssueDetailHtml(lines))`
     * equals `lines.joinToString("\n")` for every line list.
     *
     * The order makes it exact. The formatter's output holds no `<` other than the `<br>` joiner and
     * no `&` that does not start `&amp;`, `&lt;`, `&gt;` or `&nbsp;`. So `<br>` is turned back first,
     * then `&nbsp;`, `&lt;` and `&gt;`, and `&amp;` LAST, which keeps an escaped literal such as
     * `&amp;lt;` from being decoded twice.
     *
     * Why it exists (32-REVIEW CR-01): the read-time redaction rules key on a literal `&` before a
     * query or form key and on real line starts for header lines (auth, API key, cookie). The escaped
     * form has neither, so tokens and header values in stored issue text survived STRICT and BALANCED.
     *
     * Only the read paths that feed issue text to the AI backend or to an MCP client may call it
     * (`ContextCollector.fromAuditIssues`, `AuditIssue.toSerializableForm`). Never call it on a path
     * whose output Burp renders as HTML. Burp-native issue HTML passes through with only these five
     * plain substitutions.
     */
    fun issueDetailHtmlToText(html: String): String =
        html
            .replace("<br>", "\n")
            .replace("&nbsp;", " ")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")

    fun hasEquivalentIssue(
        name: String,
        baseUrl: String,
        issues: Iterable<Pair<String, String>>,
    ): Boolean {
        val canonicalName = canonicalIssueName(name)
        val normalizedUrl = normalizeUrl(baseUrl)
        return issues.any { issue ->
            normalizeUrl(issue.second) == normalizedUrl && canonicalIssueName(issue.first) == canonicalName
        }
    }

    fun hasExistingIssue(
        name: String,
        baseUrl: String,
        issues: Iterable<Pair<String, String>>,
        ignoreCase: Boolean = false,
    ): Boolean {
        val normalizedUrl = normalizeUrl(baseUrl)
        return issues.any { issue ->
            val sameName =
                if (ignoreCase) {
                    issue.first.equals(name, ignoreCase = true)
                } else {
                    issue.first == name
                }
            sameName && normalizeUrl(issue.second) == normalizedUrl
        }
    }
}
