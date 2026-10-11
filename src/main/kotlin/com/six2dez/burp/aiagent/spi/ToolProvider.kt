package com.six2dez.burp.aiagent.spi

import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import io.modelcontextprotocol.kotlin.sdk.Tool

/**
 * Phase 29 / D-13 — one MCP tool: its descriptor, its input schema and its body, kept together (D-14).
 *
 * A handler is found through the tool registry and run by `McpToolExecutor.executeToolResult`, which
 * wraps [execute] in `runTool` (toggle, unsafe and concurrency checks) and passes its result through
 * `McpToolContext.redactIfNeeded`. A handler therefore never redacts or gates anything itself: the
 * registry changes how a tool is FOUND, never what guards it.
 */
interface ToolHandler {
    /** id, title, description, category, defaultEnabled, proOnly, unsafeOnly and secTier (no default, D-03). */
    val descriptor: McpToolDescriptor

    /**
     * True for the paged tools: `count`/`limit`/`offset` are defaulted before [execute] runs
     * (`normalizePagedArgs`). Replaces the id set the executor used to keep for this.
     */
    val pagedArgs: Boolean get() = false

    fun inputSchema(context: McpToolContext?): Tool.Input

    /** The body of the former dispatch `when` branch. Runs inside `runTool`. */
    fun execute(
        args: String?,
        context: McpToolContext,
    ): String
}

/**
 * Phase 29 / D-13 — a ServiceLoader SPI that contributes tools to the catalog.
 *
 * Implementations are classes with a public no-arg constructor (a Kotlin `object` cannot be
 * instantiated by ServiceLoader, see [Plugins]). The core's native tools are registered in code, never
 * through `META-INF/services`. The registry rejects a provider whose tool id or alias is already owned
 * by another provider, so a plug-in cannot shadow a core tool and inherit its trust tier.
 */
interface ToolProvider {
    fun handlers(): List<ToolHandler>

    /** alias -> canonical tool id. The registry merges every provider's aliases into ONE table. */
    fun aliases(): Map<String, String> = emptyMap()

    /**
     * Phase 29 / D-15, D-06 — called by `McpSupervisor.applySettings` on every provider, in registry
     * order, each time MCP settings are applied (before the server starts, restarts or stops).
     *
     * A provider configures the state it owns here and reads its own preference keys through
     * [pluginSettings]; the core never names a plug-in's state or keys. [log] writes one line to Burp's
     * Output tab and adds no prefix, so the provider supplies its own. A throw is logged by the
     * supervisor and does not stop the other providers or the server.
     */
    fun onMcpSettingsApplied(
        settings: McpSettings,
        pluginSettings: PluginSettingsStore,
        log: (String) -> Unit,
    ) {}

    /**
     * Phase 29 / D-15 — called by `McpSupervisor.stop()` on every provider, in registry order, after the
     * server and the stdio bridge stopped. A provider drops the per-server state it holds (task ids,
     * client handles) so nothing outlives the server that handed it out.
     */
    fun onMcpServerStopped() {}
}
