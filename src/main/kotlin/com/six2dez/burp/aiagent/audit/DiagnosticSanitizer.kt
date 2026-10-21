package com.six2dez.burp.aiagent.audit

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.redact.SecretShapes

object DiagnosticSanitizer {
    private const val MAX_DEPTH = 8
    private val mapper = jacksonObjectMapper()
    private val sensitiveKey = Regex("(?i).*(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|credential).*")
    private val header = Regex("(?im)^\\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key)\\s*:.*$")
    private val query = Regex("""(?im)((?:^|[?&;\s])(?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey)=)[^&\s"<>]+""")
    private val providerToken = Regex("\\b(?:nvapi-[A-Za-z0-9_-]+|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\\b")

    fun sanitize(value: String): String = sanitize(value, 0)

    private fun sanitize(
        value: String,
        depth: Int,
    ): String = if (depth >= MAX_DEPTH) "[OMITTED: nesting limit]" else sanitizeValue(value, depth)

    private fun sanitizeValue(
        value: String,
        depth: Int,
    ): String {
        val parsed = runCatching { mapper.readTree(value) }.getOrNull()
        val trimmed = value.trimStart()
        val incompleteStructure = trimmed.startsWith("{") || trimmed.startsWith("[{") || trimmed.startsWith("[\"") || trimmed.startsWith("[[")
        return when {
            parsed == null && incompleteStructure -> "[OMITTED: incomplete structured data]"
            parsed?.isTextual == true -> sanitize(parsed.asText(), depth + 1)
            else -> {
                val structured = if (parsed != null && parsed.isContainerNode) mapper.writeValueAsString(clean(parsed, depth)) else value
                val masked = providerToken.replace(query.replace(header.replace(structured, "[REDACTED HEADER]"), "$1[REDACTED]"), "[REDACTED TOKEN]")
                val result = runCatching { Redaction.apply(masked, RedactionPolicy.fromMode(PrivacyMode.STRICT), stableHostSalt = "diagnostic-export") }.getOrElse { "[OMITTED: redaction failed]" }
                if (SecretShapes.findSurviving(result).isEmpty()) result else "[OMITTED: possible secret]"
            }
        }
    }

    private fun clean(
        node: JsonNode,
        depth: Int,
    ): JsonNode =
        when {
            depth >= MAX_DEPTH -> mapper.nodeFactory.textNode("[OMITTED: nesting limit]")
            node.isObject ->
                mapper.createObjectNode().also { out ->
                    node.properties().forEach { (key, value) ->
                        out.set<JsonNode>(key, if (sensitiveKey.matches(key)) mapper.nodeFactory.textNode("[REDACTED]") else clean(value, depth + 1))
                    }
                }
            node.isArray -> mapper.createArrayNode().also { out -> node.forEach { out.add(clean(it, depth + 1)) } }
            node.isTextual -> mapper.nodeFactory.textNode(sanitize(node.asText(), depth + 1))
            else -> node
        }
}
