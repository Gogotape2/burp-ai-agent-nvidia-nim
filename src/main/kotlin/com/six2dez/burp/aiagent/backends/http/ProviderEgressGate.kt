package com.six2dez.burp.aiagent.backends.http

/**
 * Phase 31 / GATE-01 — decides whether an AI-provider request may leave Burp right now.
 *
 * [MontoyaHttpTransport] consults the gate on EVERY request, as the first step of its single send
 * path, for the backend id core bound the transport to (D-04: a per-request check, no watcher and
 * no cached decision). Production builds exactly one gate: the supervisor's, which applies the
 * injected [com.six2dez.burp.aiagent.spi.AiAccessPolicy] to a live read of Burp's "Use AI" setting.
 *
 * An allow-everything gate must never exist in production code; the only one lives in the tests.
 */
fun interface ProviderEgressGate {
    /** `null` when a request for [backendId] may leave Burp now; otherwise the user-facing refusal. */
    fun refusal(backendId: String): String?
}

/**
 * Phase 31 / GATE-01 — a request refused by the [ProviderEgressGate]. It is a policy outcome, not a
 * connection failure: it is never retried, never counted by a circuit breaker, reported as
 * `Unavailable(message)` by a health check, and its message is the policy's own text.
 */
class AiAccessRefusedException(
    message: String,
) : IllegalStateException(message)
