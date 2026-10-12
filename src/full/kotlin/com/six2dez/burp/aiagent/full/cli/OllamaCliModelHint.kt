package com.six2dez.burp.aiagent.full.cli

import com.six2dez.burp.aiagent.spi.BackendModelHint
import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/** RED skeleton (29-14 Task 1). */
class OllamaCliModelHint : BackendModelHint {
    override fun defaultModel(
        backendId: String,
        store: PluginSettingsStore,
    ): String? = null
}
