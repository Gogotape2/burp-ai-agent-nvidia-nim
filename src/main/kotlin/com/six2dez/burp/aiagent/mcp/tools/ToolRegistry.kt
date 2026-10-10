package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.Tool

/**
 * Phase 29 / D-13 / D-14 — the merged, validated and ordered view of every loaded [ToolProvider].
 *
 * `McpToolExecutor.executeToolResult` finds every tool here, `McpToolCatalog` lists what is here, and
 * the MCP server registers what is here. In the store build only [NativeToolProvider] is loaded, so the
 * catalog is the native tools by construction.
 *
 * **Construction fails** (IllegalStateException naming both provider classes) when:
 * - two providers, or one provider twice, register the same tool id. A plug-in that could register
 *   `status` or `redact_preview` would inherit an AUTO tier it was never assigned (T-29-11);
 * - an alias equals a tool id, names an unknown tool, or is declared twice.
 *
 * **Order** is deterministic: the native tools first in their declared order, then the other providers
 * ordered by implementation class name (as [com.six2dez.burp.aiagent.spi.Plugins.load] does), each in
 * its declared order. It does not depend on the order of [providers].
 *
 * **Aliases** form ONE merged table. It is the only alias table in the codebase:
 * `McpToolExecutor.canonicalToolId` delegates here, and `ToolApprovalGate` calls that function rather
 * than copying it, so the tier on the approval card and the tool that executes cannot disagree.
 */
class ToolRegistry(
    providers: List<ToolProvider>,
) {
    private val handlersById: Map<String, ToolHandler>
    private val aliasTable: Map<String, String>
    private val coreIds: Set<String>
    private val orderedDescriptors: List<McpToolDescriptor>

    init {
        val (core, plugins) = providers.partition { it is NativeToolProvider }
        val ordered = core + plugins.sortedBy { it.javaClass.name }
        val owners = LinkedHashMap<String, ToolProvider>()
        val handlers = LinkedHashMap<String, ToolHandler>()
        ordered.forEach { provider -> provider.handlers().forEach { register(it, provider, owners, handlers) } }
        handlersById = handlers
        aliasTable = mergeAliases(ordered, owners)
        coreIds = core.flatMap { provider -> provider.handlers().map { it.descriptor.id } }.toSet()
        orderedDescriptors = handlers.values.map { it.descriptor }
    }

    /** Every tool, in the deterministic order described on the class. */
    fun descriptors(): List<McpToolDescriptor> = orderedDescriptors

    fun handler(id: String): ToolHandler? = handlersById[id]

    /** Trimmed, lower-cased alias lookup; anything that is not an alias comes back verbatim. */
    fun canonicalId(raw: String): String = aliasTable[raw.trim().lowercase()] ?: raw

    /** The ids supplied by [NativeToolProvider]: the tools the store build ships. */
    fun coreToolIds(): Set<String> = coreIds

    private fun register(
        handler: ToolHandler,
        provider: ToolProvider,
        owners: MutableMap<String, ToolProvider>,
        handlers: MutableMap<String, ToolHandler>,
    ) {
        val id = handler.descriptor.id
        val previous = owners.putIfAbsent(id, provider)
        if (previous != null) {
            error(
                "Tool id '$id' is registered by both ${previous.javaClass.name} and ${provider.javaClass.name}. " +
                    "A provider cannot replace another provider's tool.",
            )
        }
        handlers[id] = handler
    }

    private fun mergeAliases(
        ordered: List<ToolProvider>,
        owners: Map<String, ToolProvider>,
    ): Map<String, String> {
        val merged = LinkedHashMap<String, String>()
        val aliasOwners = HashMap<String, ToolProvider>()
        ordered.forEach { provider ->
            provider.aliases().forEach { (rawAlias, target) ->
                val alias = rawAlias.trim().lowercase()
                val toolOwner = owners[alias]
                if (toolOwner != null) {
                    error(
                        "Alias '$alias' declared by ${provider.javaClass.name} collides with the tool id owned by " +
                            "${toolOwner.javaClass.name}.",
                    )
                }
                if (target !in owners) {
                    error("Alias '$alias' declared by ${provider.javaClass.name} names unknown tool '$target'.")
                }
                val previous = aliasOwners.putIfAbsent(alias, provider)
                if (previous != null) {
                    error("Alias '$alias' is declared by both ${previous.javaClass.name} and ${provider.javaClass.name}.")
                }
                merged[alias] = target
            }
        }
        return merged
    }
}

/**
 * Builds a [ToolHandler] from its descriptor, schema and body. Handler files declare one handler per
 * tool with this factory, so each descriptor sits next to the code it describes (D-14).
 */
internal fun toolHandler(
    descriptor: McpToolDescriptor,
    pagedArgs: Boolean = false,
    schema: (McpToolContext?) -> Tool.Input,
    execute: (String?, McpToolContext) -> String,
): ToolHandler = FunctionToolHandler(descriptor, pagedArgs, schema, execute)

private class FunctionToolHandler(
    override val descriptor: McpToolDescriptor,
    override val pagedArgs: Boolean,
    private val schema: (McpToolContext?) -> Tool.Input,
    private val body: (String?, McpToolContext) -> String,
) : ToolHandler {
    override fun inputSchema(context: McpToolContext?): Tool.Input = schema(context)

    override fun execute(
        args: String?,
        context: McpToolContext,
    ): String = body(args, context)
}
