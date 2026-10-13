package com.six2dez.burp.aiagent.backends

import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/**
 * Phase 29 / D-06 — a backend whose configuration lives in plug-in preference keys rather than in the
 * core `AgentSettings` snapshot (the full build's CLI backends).
 *
 * [BackendRegistry] remembers the store it was given and applies it to every such backend it creates,
 * on each reload, exactly as it does for [HttpTransportAware]. Until a store is applied the backend
 * uses its built-in defaults.
 */
interface PluginSettingsAware {
    fun setPluginSettings(store: PluginSettingsStore)
}
