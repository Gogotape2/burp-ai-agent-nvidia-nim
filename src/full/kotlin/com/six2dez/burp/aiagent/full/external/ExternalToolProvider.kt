package com.six2dez.burp.aiagent.full.external

import com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider

/** RED skeleton (29-15 Task 2): replaced by the implementation in the GREEN commit. */
@Suppress("UnusedPrivateProperty")
class ExternalToolProvider(
    private val managerSource: () -> ExternalMcpClientManager? = { null },
) : ToolProvider {
    override fun handlers(): List<ToolHandler> = emptyList()

    companion object {
        @Suppress("UnusedParameter")
        internal fun parseArgsMapOrEmpty(json: String): Map<String, Any?> = emptyMap()
    }
}
