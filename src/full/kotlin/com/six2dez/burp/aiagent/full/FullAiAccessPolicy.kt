package com.six2dez.burp.aiagent.full

import com.six2dez.burp.aiagent.spi.AiAccessPolicy

/**
 * Phase 29 / BUILD-04 — the full (GitHub) build's [AiAccessPolicy], registered through
 * `META-INF/services/com.six2dez.burp.aiagent.spi.AiAccessPolicy`, a file only the full JAR carries.
 *
 * It keeps the 1.0.1 behavior: Burp's "Use AI" setting gates only the `burp-ai` backend, which
 * delegates inference to Burp's bundled AI. Every other backend (local and cloud HTTP providers, CLI
 * agents) is independent of that setting and keeps working while it is off, including in Burp
 * Community, where the setting does not exist.
 *
 * A class rather than an `object`: ServiceLoader needs a public no-arg constructor.
 */
class FullAiAccessPolicy : AiAccessPolicy {
    override fun refusal(
        backendId: String,
        burpAiEnabled: Boolean,
    ): String? = if (backendId == BURP_AI_BACKEND_ID && !burpAiEnabled) REFUSAL else null

    private companion object {
        const val BURP_AI_BACKEND_ID = "burp-ai"
        const val REFUSAL = "Burp AI is disabled in Burp Suite settings. Enable 'Use AI' for extensions, or pick a different backend."
    }
}
