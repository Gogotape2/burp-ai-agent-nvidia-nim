package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider

/**
 * Phase 29 / D-13 / D-14 — the generic Montoya tools, contributed through ServiceLoader
 * (`META-INF/services/com.six2dez.burp.aiagent.spi.ToolProvider`).
 *
 * The catalog is "what the loaded providers supply", so once plan 29-11 moves this class and its
 * services file into `src/full`, the store build's tool list is the native tools by construction.
 * Each descriptor was moved verbatim from McpToolCatalog's list, in its old order.
 *
 * Residual delegation (until plan 29-08): every handler here delegates its body and schema to
 * `McpToolExecutor.dispatchGenericTool` / `genericInputSchema`, which hold the remaining generic
 * `when` branches.
 */
class GenericToolProvider : ToolProvider {
    override fun handlers(): List<ToolHandler> = genericDescriptors.map(::delegatingHandler)

    override fun aliases(): Map<String, String> = GENERIC_ALIASES
}

/**
 * The model-facing shorthands for the history and site-map tools. The registry merges this into the
 * single alias table `McpToolExecutor.canonicalToolId` reads.
 */
private val GENERIC_ALIASES: Map<String, String> =
    mapOf(
        "history" to "proxy_http_history",
        "proxy_history" to "proxy_http_history",
        "requests" to "proxy_http_history",
        "history_regex" to "proxy_http_history_regex",
        "proxy_history_regex" to "proxy_http_history_regex",
        "ws_history" to "proxy_ws_history",
        "websocket_history" to "proxy_ws_history",
        "websocket" to "proxy_ws_history",
        "sitemap" to "site_map",
        "site_map_history" to "site_map",
    )

/** The tools whose `count`/`limit`/`offset` arguments are defaulted before they run. */
private val PAGED_TOOL_IDS: Set<String> =
    setOf(
        "proxy_http_history",
        "proxy_http_history_regex",
        "response_body_search",
        "proxy_ws_history",
        "proxy_ws_history_regex",
        "site_map",
        "site_map_regex",
        "scanner_issues",
    )

private fun delegatingHandler(descriptor: McpToolDescriptor): ToolHandler =
    toolHandler(
        descriptor = descriptor,
        pagedArgs = descriptor.id in PAGED_TOOL_IDS,
        schema = { context -> McpToolExecutor.genericInputSchema(descriptor.id, context) },
    ) { args, context -> McpToolExecutor.dispatchGenericTool(descriptor.id, args, context) }

private val genericDescriptors: List<McpToolDescriptor> =
    listOf(
        McpToolDescriptor(
            id = "url_encode",
            title = "URL encode",
            description = "URL encodes the input string.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "url_decode",
            title = "URL decode",
            description = "URL decodes the input string.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "base64_encode",
            title = "Base64 encode",
            description = "Base64 encodes the input string.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "base64_decode",
            title = "Base64 decode",
            description = "Base64 decodes the input string.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "random_string",
            title = "Generate random string",
            description = "Generates a random string of specified length and character set.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "hash_compute",
            title = "Compute hash",
            description = "Computes a hash for input text (MD5/SHA1/SHA256/SHA512).",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "jwt_decode",
            title = "Decode JWT",
            description = "Decodes JWT header/payload without verifying the signature.",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "decode_as",
            title = "Decode content",
            description = "Decodes base64 content using compression codecs (gzip/deflate/brotli).",
            category = "Utilities",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "cookie_jar_get",
            title = "Cookie jar",
            description = "Returns cookies from Burp's cookie jar (values redacted unless privacy is OFF).",
            category = "Utilities",
            defaultEnabled = true,
            // CONFIRM, tiered for its worst case (PrivacyMode.OFF with includeValues): the tier must not depend on privacy mode — a mode-dependent trust boundary is the same defect D-01 rejects for unsafeOnly.
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_http_history",
            title = "Proxy HTTP history",
            description = "Displays items within the proxy HTTP history.",
            category = "History",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_http_history_regex",
            title = "Proxy HTTP history (regex)",
            description = "Displays proxy HTTP history items matching a regex.",
            category = "History",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_history_annotate",
            title = "Annotate proxy history",
            description = "Adds notes/highlights to proxy history items matching a regex.",
            category = "History",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "response_body_search",
            title = "Search response bodies",
            description = "Searches response bodies in proxy history using a regex.",
            category = "History",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_ws_history",
            title = "Proxy WebSocket history",
            description = "Displays items within the proxy WebSocket history.",
            category = "History",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_ws_history_regex",
            title = "Proxy WebSocket history (regex)",
            description = "Displays WebSocket history items matching a regex.",
            category = "History",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "site_map",
            title = "Site map",
            description = "Displays items within the Burp site map.",
            category = "Site Map",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "site_map_regex",
            title = "Site map (regex)",
            description = "Displays site map items matching a regex.",
            category = "Site Map",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "scope_check",
            title = "Scope check",
            description = "Checks whether a URL is in scope.",
            category = "Scope",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "scope_include",
            title = "Include in scope",
            description = "Includes a URL in scope.",
            category = "Scope",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "scope_exclude",
            title = "Exclude from scope",
            description = "Excludes a URL from scope.",
            category = "Scope",
            defaultEnabled = false,
            unsafeOnly = true,
            // CONFIRM, not CONFIRM_EACH: excluding narrows the blast radius where scope_include widens it. The asymmetry is the point.
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "scanner_issues",
            title = "Scanner issues",
            description = "Displays scanner issues (Burp Pro only).",
            category = "Scanner",
            defaultEnabled = true,
            proOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "http1_request",
            title = "Send HTTP/1.1 request",
            description = "Issues an HTTP/1.1 request and returns the response.",
            category = "Requests",
            defaultEnabled = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "http2_request",
            title = "Send HTTP/2 request",
            description = "Issues an HTTP/2 request and returns the response.",
            category = "Requests",
            defaultEnabled = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "repeater_tab",
            title = "Create repeater tab",
            description = "Creates a new Repeater tab with the specified HTTP request.",
            category = "Requests",
            defaultEnabled = false,
            unsafeOnly = true,
            // CONFIRM_EACH under ADR-15's "or stage it for one click" clause — the same clause that tiers intruder / intruder_prepare.
            // McpToolExecutorImpl.kt:243-256 builds an HttpRequest from model-supplied `content` and hands it to sendToRepeater, so the
            // request sits one Send click from the wire. It shipped as CONFIRM, which let one approve-for-session click cover every later
            // call with DIFFERENT request content in that chat; the content is the whole attack surface, so per-call is the only defensible tier.
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "repeater_tab_with_payload",
            title = "Create repeater tab with payload",
            description = "Creates a Repeater tab after applying placeholder replacements.",
            category = "Requests",
            defaultEnabled = false,
            unsafeOnly = true,
            // CONFIRM_EACH for the same ADR-15 clause as `repeater_tab` above, and with slightly more reason: McpToolExecutorImpl.kt:261
            // runs applyReplacements(input.content, input.replacements) BEFORE staging, so the request content and the substituted
            // payloads are both model-supplied. Placeholder substitution running first does not make the staged request any less
            // model-authored — it widens what one approve-for-session click would have covered.
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "intruder",
            title = "Send to Intruder",
            description = "Sends a request to Intruder.",
            category = "Requests",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "intruder_prepare",
            title = "Prepare Intruder tab",
            description = "Creates an Intruder tab with explicit insertion points.",
            category = "Requests",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "insertion_points",
            title = "List insertion points",
            description = "Lists insertion point offsets for a request.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "params_extract",
            title = "Extract parameters",
            description = "Extracts parameters from a request.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "diff_requests",
            title = "Diff requests",
            description = "Produces a line diff between two requests.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "request_parse",
            title = "Parse request",
            description = "Parses a raw HTTP request into method, path, headers, parameters, and body.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "response_parse",
            title = "Parse response",
            description = "Parses a raw HTTP response into status, headers, and body.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "find_reflected",
            title = "Find reflected values",
            description = "Finds reflected parameter values in a response.",
            category = "Requests",
            defaultEnabled = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "comparer_send",
            title = "Send to Comparer",
            description = "Sends one or more items to Burp Comparer.",
            category = "Requests",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "task_engine_state",
            title = "Set task execution engine state",
            description = "Sets Burp's task execution engine to paused or running.",
            category = "Burp Control",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "proxy_intercept",
            title = "Set proxy intercept state",
            description = "Enables or disables Proxy intercept.",
            category = "Burp Control",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "editor_get",
            title = "Get active editor contents",
            description = "Outputs the contents of the active message editor.",
            category = "Editor",
            defaultEnabled = false,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "editor_set",
            title = "Set active editor contents",
            description = "Sets the content of the active message editor.",
            category = "Editor",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "project_options_get",
            title = "Output project options",
            description = "Outputs project-level configuration as JSON.",
            category = "Config",
            defaultEnabled = false,
            // CONFIRM despite being read-only — the data is not attacker-controlled, but it is the user's own credential material (ADR-15, Pitfall 1).
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "user_options_get",
            title = "Output user options",
            description = "Outputs user-level configuration as JSON.",
            category = "Config",
            defaultEnabled = false,
            // CONFIRM despite being read-only — the data is not attacker-controlled, but it is the user's own credential material (ADR-15, Pitfall 1).
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "project_options_set",
            title = "Set project options",
            description = "Sets project-level configuration from JSON.",
            category = "Config",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "user_options_set",
            title = "Set user options",
            description = "Sets user-level configuration from JSON.",
            category = "Config",
            defaultEnabled = false,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "collaborator_generate",
            title = "Generate Collaborator payload",
            description = "Generates a Burp Collaborator payload.",
            category = "Collaborator",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "collaborator_poll",
            title = "Poll Collaborator interactions",
            description = "Fetches interactions for a Collaborator secret key.",
            category = "Collaborator",
            defaultEnabled = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "scan_audit_start",
            title = "Start scanner audit",
            description = "Starts a Burp Scanner audit.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "scan_audit_start_mode",
            title = "Start scanner audit (mode)",
            description = "Starts a scanner audit using active or passive mode.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "scan_audit_start_requests",
            title = "Start audit with requests",
            description = "Starts an audit and adds HTTP requests.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "scan_crawl_start",
            title = "Start crawl",
            description = "Starts a Burp Scanner crawl.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
        McpToolDescriptor(
            id = "scan_task_status",
            title = "Get scan task status",
            description = "Gets status for a crawl/audit task.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            secTier = SecTier.AUTO,
        ),
        McpToolDescriptor(
            id = "scan_task_delete",
            title = "Delete scan task",
            description = "Deletes a crawl/audit task started via MCP.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM,
        ),
        McpToolDescriptor(
            id = "scan_report",
            title = "Generate scanner report",
            description = "Generates a scanner report to a path.",
            category = "Scanner",
            defaultEnabled = false,
            proOnly = true,
            unsafeOnly = true,
            secTier = SecTier.CONFIRM_EACH,
        ),
    )
