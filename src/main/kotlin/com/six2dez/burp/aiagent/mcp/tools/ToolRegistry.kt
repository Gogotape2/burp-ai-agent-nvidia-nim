package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.Tool

// RED scaffolding: compiles, validates nothing. Replaced in the GREEN commit.
class ToolRegistry(
    providers: List<ToolProvider>,
) {
    private val handlers = providers.flatMap { it.handlers() }

    fun descriptors(): List<McpToolDescriptor> = handlers.map { it.descriptor }

    fun handler(id: String): ToolHandler? = handlers.firstOrNull { it.descriptor.id == id }

    fun canonicalId(raw: String): String = raw

    fun coreToolIds(): Set<String> = emptySet()
}

internal fun toolHandler(
    descriptor: McpToolDescriptor,
    pagedArgs: Boolean = false,
    schema: (McpToolContext?) -> Tool.Input,
    execute: (String?, McpToolContext) -> String,
): ToolHandler =
    object : ToolHandler {
        override val descriptor: McpToolDescriptor = descriptor
        override val pagedArgs: Boolean = pagedArgs

        override fun inputSchema(context: McpToolContext?): Tool.Input = schema(context)

        override fun execute(
            args: String?,
            context: McpToolContext,
        ): String = execute(args, context)
    }
