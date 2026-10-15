package com.six2dez.burp.aiagent

import burp.api.montoya.BurpExtension
import burp.api.montoya.EnhancedCapability
import burp.api.montoya.MontoyaApi

class BurpAiAgentExtension : BurpExtension {
    override fun enhancedCapabilities(): Set<EnhancedCapability> = setOf(EnhancedCapability.AI_FEATURES)

    /**
     * Phase 33 / D-07, LIFE-02 — the unloading handler is registered BEFORE [App.initialize] runs, so
     * whatever the load started (the MCP listener first of all) always has an unload path.
     *
     * Whether Burp calls a registered handler when initialize throws is not documented, so a load that
     * throws cleans up itself: the catch runs [App.shutdown]. Shutdown is idempotent, so the handler
     * running afterwards as well is harmless. The original exception is rethrown, so Burp still reports
     * the failed load instead of a half-loaded extension that looks healthy.
     *
     * Both paths pass `shutdownSharedCoroutines = true`: this is the production unload path, the only one
     * allowed to run the guarded, irreversible shared coroutine shutdown (D-12).
     */
    @Suppress("TooGenericExceptionCaught") // any load failure, Error included, must be cleaned up and rethrown
    override fun initialize(api: MontoyaApi) {
        api.extension().registerUnloadingHandler {
            App.shutdown(shutdownSharedCoroutines = true)
        }
        try {
            App.initialize(api)
        } catch (t: Throwable) {
            App.shutdown(shutdownSharedCoroutines = true)
            throw t
        }
    }
}
