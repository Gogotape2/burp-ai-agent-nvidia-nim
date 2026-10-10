package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.BuildFlags
import com.six2dez.burp.aiagent.mcp.tools.NativeToolProvider
import com.six2dez.burp.aiagent.mcp.tools.ToolRegistry
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.ToolProvider

/**
 * SEC-06 trust tier for a catalog tool: how much human authorisation one model-emitted invocation
 * needs. The wire string is defined once, here, and nowhere else — the approval card and any audit
 * payload both read [wireValue], so the two sinks cannot disagree.
 *
 * [AUTO] means read-only AND bounded output. A tool qualifies only if it neither mutates Burp state
 * nor pulls bulk attacker-controlled traffic into model context (D-05). That sentence is the whole
 * definition; the familiar examples (decoders, schema/catalog lookups, scope reads) illustrate it
 * but do not extend it. Consequence: `proxy_http_history`, `site_map` and `scanner_issues` are
 * read-only yet are [CONFIRM], because what they return is bulk attacker-controlled traffic.
 *
 * This tier is a SECOND, INDEPENDENT axis from [McpToolDescriptor.unsafeOnly] (D-01). `unsafeOnly`
 * is a *capability* switch — may this tool ever run at all — while `secTier` is a *trust* axis —
 * did a human authorise this particular invocation. Neither is derivable from the other:
 * `ai_analyze` and `ai_passive_scan` are [CONFIRM_EACH] without being `unsafeOnly` at all, so
 * binding the trust boundary to `unsafeOnly` would leave both of them ungated.
 */
enum class SecTier(
    val wireValue: String,
) {
    /** Runs silently, with no user decision at all (D-02). Read-only AND bounded output. */
    AUTO("auto"),

    /** Prompts, and the user may approve this tool for the rest of the session (D-02). */
    CONFIRM("confirm"),

    /** Prompts on every single call; no session memory in either direction (D-02). */
    CONFIRM_EACH("confirm_each"),
}

data class McpToolDescriptor(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val defaultEnabled: Boolean,
    val proOnly: Boolean = false,
    val unsafeOnly: Boolean = false,
    // D-03: deliberately has NO default value. A default is how a new tool silently inherits a tier
    // nobody chose; the compile error at the catalog site is the control.
    val secTier: SecTier,
    val nativeTool: Boolean = false, // true = extension-native; present in the BApp Store build
)

object McpToolCatalog {
    // RED scaffolding: the registry exists but the catalog still reads its own list.
    internal val registry: ToolRegistry by lazy { ToolRegistry(listOf(NativeToolProvider()) + Plugins.load(ToolProvider::class.java)) }

    fun coreToolIds(): Set<String> = registry.coreToolIds()

    private val tools =
        listOf(
            McpToolDescriptor(
                id = "status",
                title = "Extension status",
                description = "Returns basic extension and Burp version status.",
                category = "Extension",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
                nativeTool = true,
            ),
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
            McpToolDescriptor(
                id = "issue_create",
                title = "Create audit issue",
                description = "Creates a custom audit issue in Burp's issue list for AI-discovered findings.",
                category = "Issues",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "ai_analyze",
                title = "AI Analyze",
                description = "Sends text to the active AI backend and returns the analysis result.",
                category = "AI",
                defaultEnabled = true,
                // CONFIRM_EACH while NOT unsafeOnly — D-01's independence claim made concrete: binding the trust boundary to unsafeOnly would leave this ungated.
                secTier = SecTier.CONFIRM_EACH,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "ai_passive_scan",
                title = "AI Passive Scan",
                description = "Queues requests for AI passive security analysis and returns the count enqueued.",
                category = "AI",
                defaultEnabled = true,
                // CONFIRM_EACH while NOT unsafeOnly — D-01's independence claim made concrete: binding the trust boundary to unsafeOnly would leave this ungated.
                secTier = SecTier.CONFIRM_EACH,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "ai_findings_recent",
                title = "AI Recent Findings",
                description = "Returns the most recent AI passive scan findings (up to n).",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "redact_preview",
                title = "Redact Preview",
                description = "Applies the extension's privacy redaction engine to arbitrary text and returns the redacted result.",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "ai_audit_query",
                title = "AI Audit Query",
                description = "Returns recent AI request audit log entries (hashes only unless verbose mode is enabled).",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
                nativeTool = true,
            ),
            McpToolDescriptor(
                id = "ai_backends_list",
                title = "AI Backends List",
                description = "Lists available AI backends and reports the current active backend and connection state.",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
                nativeTool = true,
            ),
        )

    fun all(): List<McpToolDescriptor> = tools

    fun available(storeBuild: Boolean = BuildFlags.STORE_BUILD): List<McpToolDescriptor> = if (storeBuild) tools.filter { it.nativeTool } else tools

    fun defaults(): Map<String, Boolean> = tools.associate { it.id to it.defaultEnabled }

    fun unsafeToolIds(): Set<String> = tools.filter { it.unsafeOnly }.map { it.id }.toSet()

    fun mergeWithDefaults(overrides: Map<String, Boolean>): Map<String, Boolean> {
        val merged = defaults().toMutableMap()
        overrides.forEach { (k, v) -> merged[k] = v }
        return merged
    }
}
