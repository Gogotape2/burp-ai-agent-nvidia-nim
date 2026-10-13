package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
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

    /**
     * Phase 29 / D-15, D-06 (T-29-40) — this provider owns the scanner-task and Collaborator registries
     * and their TTLs. It reads its own keys (the 1.0.1 names, unchanged, so an upgraded install keeps
     * its values - D-11), clamps them to [MIN_TTL_MINUTES]..[MAX_TTL_MINUTES] and never writes them
     * (D-08). The core no longer holds, reads or writes either key.
     */
    override fun onMcpSettingsApplied(
        settings: McpSettings,
        pluginSettings: PluginSettingsStore,
        log: (String) -> Unit,
    ) {
        ScannerTaskRegistry.configureTtlMinutes(ttlMinutes(pluginSettings, SCAN_TASK_TTL_KEY, DEFAULT_SCAN_TASK_TTL_MINUTES))
        CollaboratorRegistry.configureTtlMinutes(
            ttlMinutes(pluginSettings, COLLABORATOR_TTL_KEY, DEFAULT_COLLABORATOR_TTL_MINUTES),
        )
        ScannerTaskRegistry.setLogger { log("[ScannerTaskRegistry] $it") }
        CollaboratorRegistry.setLogger { log("[CollaboratorRegistry] $it") }
    }

    /** Scanner task ids and Collaborator clients never outlive the MCP server that handed them out. */
    override fun onMcpServerStopped() {
        ScannerTaskRegistry.clear()
        CollaboratorRegistry.clear()
    }

    private fun ttlMinutes(
        pluginSettings: PluginSettingsStore,
        key: String,
        default: Int,
    ): Int = (pluginSettings.getInteger(key) ?: default).coerceIn(MIN_TTL_MINUTES, MAX_TTL_MINUTES)

    private companion object {
        const val SCAN_TASK_TTL_KEY = "mcp.scan.task.ttl.minutes"
        const val COLLABORATOR_TTL_KEY = "mcp.collaborator.ttl.minutes"
        const val DEFAULT_SCAN_TASK_TTL_MINUTES = 120
        const val DEFAULT_COLLABORATOR_TTL_MINUTES = 60
        const val MIN_TTL_MINUTES = 5
        const val MAX_TTL_MINUTES = 24 * 60
    }
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
