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
 *
 * The utility, history, site-map, config and editor tools are real handlers next to their descriptors
 * (GenericUtilityTools.kt, GenericHistoryTools.kt, GenericSiteMapTools.kt, GenericConfigTools.kt).
 * Residual delegation (until plan 29-08): the request, scanner and collaborator handlers below still
 * delegate their body and schema to `McpToolExecutor.dispatchGenericTool` / `genericInputSchema`, and
 * their descriptors, moved verbatim from McpToolCatalog's list, stay here until then.
 */
class GenericToolProvider : ToolProvider {
    override fun handlers(): List<ToolHandler> =
        genericUtilityHandlers +
            genericHistoryHandlers +
            genericSiteMapHandlers +
            genericConfigHandlers +
            delegatedDescriptors.map(::delegatingHandler)

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

/**
 * The delegating tools whose `count`/`limit`/`offset` arguments are defaulted before they run. The
 * converted paged tools declare `pagedArgs = true` on their own handler.
 */
private val PAGED_TOOL_IDS: Set<String> = setOf("scanner_issues")

private fun delegatingHandler(descriptor: McpToolDescriptor): ToolHandler =
    toolHandler(
        descriptor = descriptor,
        pagedArgs = descriptor.id in PAGED_TOOL_IDS,
        schema = { McpToolExecutor.genericInputSchema(descriptor.id) },
    ) { args, context -> McpToolExecutor.dispatchGenericTool(descriptor.id, args, context) }

/** Request, scanner and collaborator descriptors, still dispatched by `McpToolExecutor.dispatchGenericTool`. */
private val delegatedDescriptors: List<McpToolDescriptor> =
    listOf(
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
