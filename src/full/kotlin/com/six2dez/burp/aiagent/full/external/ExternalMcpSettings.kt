package com.six2dez.burp.aiagent.full.external

import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/** RED skeleton (29-15 Task 1): replaced by the implementation in the GREEN commit. */
class ExternalMcpSettings internal constructor(
    private val store: PluginSettingsStore,
    private val logError: (String) -> Unit,
    private val parse: (String) -> List<ExternalMcpServerConfig>,
) {
    constructor(store: PluginSettingsStore, logError: (String) -> Unit) : this(store, logError, { emptyList() })

    fun load(): List<ExternalMcpServerConfig> = emptyList()

    fun save(configs: List<ExternalMcpServerConfig>) {
        // RED skeleton: writes nothing.
    }

    companion object {
        const val KEY: String = "mcp.external.servers.v1"
    }
}
