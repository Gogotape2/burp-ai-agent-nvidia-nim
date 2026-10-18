package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ShutdownDeadline

interface McpServerManager {
    fun setAiRequestLogger(logger: AiRequestLogger)

    fun setAiToolDependencies(
        supervisor: AgentSupervisor,
        passiveScanner: PassiveAiScanner,
        backendRegistry: BackendRegistry,
    )

    fun start(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings,
        callback: (McpServerState) -> Unit,
    )

    fun stop(callback: (McpServerState) -> Unit)

    fun shutdown()

    /**
     * Phase 33 / D-05 — the terminal shutdown, waiting only for what is left of the shared unload
     * [deadline]. The default delegates to [shutdown] so test fakes need no change; the real manager
     * overrides it.
     */
    fun shutdown(deadline: ShutdownDeadline) {
        shutdown()
    }
}
