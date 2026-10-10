package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider

/**
 * Phase 29 / D-13 / D-14 — the generic Montoya tools, contributed through ServiceLoader
 * (`META-INF/services/com.six2dez.burp.aiagent.spi.ToolProvider`).
 *
 * The catalog is "what the loaded providers supply", so once plan 29-11 moves this class and its
 * services file into `src/full`, the store build's tool list is the native tools by construction.
 *
 * Every generic tool is a real handler next to its descriptor, in six group files:
 * GenericUtilityTools.kt, GenericHistoryTools.kt, GenericSiteMapTools.kt, GenericConfigTools.kt,
 * GenericRequestTools.kt and GenericScannerTools.kt (scanner + Collaborator). This class only
 * concatenates the group lists and declares the model-facing aliases.
 */
class GenericToolProvider : ToolProvider {
    override fun handlers(): List<ToolHandler> =
        genericUtilityHandlers +
            genericHistoryHandlers +
            genericSiteMapHandlers +
            genericConfigHandlers +
            genericRequestHandlers +
            genericScannerHandlers

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
