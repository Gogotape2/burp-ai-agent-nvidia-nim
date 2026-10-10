package com.six2dez.burp.aiagent.spi

/**
 * Phase 29 / BUILD-04 — decides whether a request to an AI backend may start, given the state of
 * Burp's "Use AI" setting. The behavior that differs between the two builds lives here, behind an
 * injected policy, instead of in a flavor branch.
 *
 * At most one provider may be registered through `META-INF/services`. With none (the BApp Store JAR)
 * the core [StoreAiAccessPolicy] is used. With more than one, the caller also falls back to
 * [StoreAiAccessPolicy] and reports the conflict: a packaging error must leave the build stricter,
 * never laxer.
 *
 * Providers MUST be classes with a public no-arg constructor (see [Plugins]).
 */
interface AiAccessPolicy {
    /**
     * `null` when a request to [backendId] is allowed; otherwise the user-facing message that explains
     * the refusal. [burpAiEnabled] is the current value of Burp's "Use AI" setting (always `false` in
     * Burp Community, where the setting does not exist).
     */
    fun refusal(
        backendId: String,
        burpAiEnabled: Boolean,
    ): String?
}

/**
 * RED scaffolding (29-07 Task 1): allows everything. Replaced by the real strict policy in GREEN.
 */
class StoreAiAccessPolicy : AiAccessPolicy {
    override fun refusal(
        backendId: String,
        burpAiEnabled: Boolean,
    ): String? = null
}
