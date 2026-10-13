package com.six2dez.burp.aiagent.backends.http

import burp.api.montoya.MontoyaApi

/**
 * Phase 31 / GATE-01 — test-only transports for tests that drive the REAL
 * `MontoyaHttpTransport.execute` path.
 *
 * Production builds exactly one transport, gated by the supervisor's access policy, and a gate-less
 * transport refuses every request. Tests that need a request to reach a mocked Burp HTTP stack use
 * [open], whose [ALLOW_ALL] gate exists only here in src/test: an allow-everything gate must never
 * ship, because it would let provider traffic leave Burp while "Use AI" is off.
 */
internal object TestTransports {
    /** Allows every request. Test code only. */
    val ALLOW_ALL: ProviderEgressGate = ProviderEgressGate { null }

    /** An allowing transport already bound to [backendId]. */
    fun open(
        api: MontoyaApi,
        backendId: String = "test",
    ): MontoyaHttpTransport = MontoyaHttpTransport(api, ALLOW_ALL).forBackend(backendId)

    /** A transport bound to [backendId] whose gate refuses every request with [refusal]. */
    fun refusing(
        api: MontoyaApi,
        refusal: String,
        backendId: String = "test",
    ): MontoyaHttpTransport = MontoyaHttpTransport(api) { refusal }.forBackend(backendId)
}
