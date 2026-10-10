package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.config.McpSettings
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/**
 * SEC-07 / SC2 — Finding 7, asserted against a real hostile listener.
 *
 * The scenario is the one the finding describes: a local process binds `127.0.0.1:<mcp port>` before
 * Burp does, answers `GET /__mcp/health` with `200` **and a spoofed `X-Burp-AI-Agent: mcp` response
 * header**, and waits for the extension's bind-conflict takeover to hand it something. Before Phase 25
 * it was handed `Authorization: Bearer <token>` — full MCP tool access to the operator's Burp.
 *
 * The squatter here is `okhttp3.mockwebserver.MockWebServer` — the legacy package, matching the
 * existing in-repo call sites in the backend tests.
 *
 * Naming note, inherited verbatim from `McpTestServerSupport.kt`: test classes in this package MUST
 * NOT be named `*IntegrationTest`, `*ConcurrencyTest`, `*BackpressureTest`, `*RestartPolicyTest` or
 * `*SupervisionTest`. The `excludeHeavyTests` filter block inside `tasks.test` in `build.gradle.kts`
 * excludes exactly those globs under `-PexcludeHeavyTests=true`, so a security gate wearing one of
 * those suffixes would be silently skipped in a fast PR gate and prove nothing.
 */
class McpTakeoverSquatterTest {
    private lateinit var squatter: MockWebServer
    private val api = McpTestServerSupport.deepStubApi()
    private val supervisor = McpSupervisor(api)

    @BeforeEach
    fun setUp() {
        squatter = MockWebServer()
        // Bound explicitly to 127.0.0.1 because `McpTestServerSupport.localSettings` builds settings
        // for that literal host, and the takeover client dials the settings host — not the server's
        // own reported hostname.
        squatter.start(InetAddress.getByName("127.0.0.1"), 0)
    }

    @AfterEach
    fun tearDown() {
        supervisor.shutdown()
        squatter.shutdown()
    }

    @Test
    fun aLocalSquatterThatSpoofsTheIdentityHeaderNeverReceivesTheToken() {
        squatter.dispatcher = spoofingDispatcher(shutdownCode = 200)

        assertEquals(
            "SHUTDOWN_REQUESTED",
            attemptTakeover(squatterSettings()),
            "The spoofed identity header still convinces the probe — that is the point. Identity is not " +
                "what protects the credential any more; the credential being worthless is.",
        )

        assertNoTokenReached(recordedShutdownRequest())
    }

    @Test
    fun anExternalModeSquatterAlsoReceivesNoToken() {
        // The sharper half of Finding 7 and it needs its own assertion. In external mode
        // probeExistingServer does not inspect the identity header at all — its verdict is
        // `alive && (externalEnabled || header == "mcp")` — so LIVENESS ALONE reaches the shutdown
        // request. A squatter does not even have to bother spoofing.
        squatter.dispatcher = spoofingDispatcher(shutdownCode = 200)

        assertEquals(
            "SHUTDOWN_REQUESTED",
            attemptTakeover(squatterSettings().copy(externalEnabled = true)),
            "In external mode liveness alone must still reach the shutdown request, otherwise " +
                "attemptTakeover returns NO_COMPATIBLE_SERVER and handleBindFailure schedules no retry",
        )

        assertNoTokenReached(recordedShutdownRequest())
    }

    @Test
    fun aListenerThatRejectsTheProofYieldsShutdownRejected() {
        // A-25-06: a NEW client talking to an OLD (v0.9.x) server gets 401, because the old server only
        // knows the bearer form. The outcome must be a visible refusal — the MCP server stays down and
        // says so — never a retry with a different credential and never a leak.
        squatter.dispatcher = spoofingDispatcher(shutdownCode = 401)

        assertEquals(
            "SHUTDOWN_REJECTED",
            attemptTakeover(squatterSettings()),
            "A listener that refuses the proof must surface as SHUTDOWN_REJECTED",
        )

        assertNoTokenReached(recordedShutdownRequest())
    }

    @Test
    fun theTakeoverClientHoldsTheTokenOnlyAsAnHmacKey() {
        // The structural invariant behind the assumption-delta `promote` decision: the primary noun is
        // now proof-of-possession, not the token itself, and NO client path retains the old credential.
        // Behavioural tests above prove the current client is clean; this one goes red the moment a
        // future phase puts the secret back on the wire under ANY header name, including one no
        // behavioural assertion here anticipates.
        // SourceRoots.file fails naming both production roots when the file is in neither or in both.
        val source = SourceRoots.file(SUPERVISOR_SOURCE).readText()

        val carrying = source.lines().filter { it.contains(TOKEN_PROPERTY) }
        assertEquals(
            1,
            carrying.size,
            "`$TOKEN_PROPERTY` must appear exactly once in McpSupervisor.kt. Found ${carrying.size} " +
                "occurrence(s): $carrying. More than one means the MCP token is being read somewhere " +
                "other than the single HMAC-key argument, which is how Finding 7 gets reopened.",
        )
        assertTrue(
            carrying.single().contains("McpTakeoverProof.forTarget"),
            "The one line reading the token must be the HMAC key argument, not a header value. Found: " +
                "`${carrying.single().trim()}`",
        )
    }

    /**
     * The squatter: `200` plus the spoofed identity header on the probe, and a configurable status on
     * the shutdown request so A-25-06's refusal path can be driven too.
     */
    private fun spoofingDispatcher(shutdownCode: Int): Dispatcher =
        object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse =
                when (request.path) {
                    HEALTH_PATH ->
                        MockResponse()
                            .setResponseCode(200)
                            // Trivially spoofable by whoever holds the port — that IS Finding 7.
                            .addHeader("X-Burp-AI-Agent", "mcp")
                            .setBody("ok")

                    SHUTDOWN_PATH -> MockResponse().setResponseCode(shutdownCode)
                    else -> MockResponse().setResponseCode(404)
                }
        }

    private fun squatterSettings(): McpSettings = McpTestServerSupport.localSettings(squatter.port, token = SQUATTER_TOKEN)

    /**
     * Drives the private bind-conflict path by reflection — the idiom `McpSupervisorProbeTest.probe`
     * establishes — and returns the outcome by NAME, because `BindTakeoverOutcome` is a private nested
     * enum and is not nameable from a test.
     */
    private fun attemptTakeover(settings: McpSettings): String {
        val method = supervisor.javaClass.getDeclaredMethod("attemptTakeover", McpSettings::class.java)
        method.isAccessible = true
        return (method.invoke(supervisor, settings) as Enum<*>).name
    }

    /** The takeover issues the health probe first, then the shutdown; this skips to the POST. */
    private fun recordedShutdownRequest(): RecordedRequest {
        repeat(MAX_RECORDED_REQUESTS) {
            val recorded =
                squatter.takeRequest(TAKE_REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    ?: error("The squatter recorded no further request; the shutdown request was never issued")
            if (recorded.method == "POST" && recorded.path == SHUTDOWN_PATH) return recorded
        }
        error("The squatter never received POST $SHUTDOWN_PATH")
    }

    private fun assertNoTokenReached(shutdown: RecordedRequest) {
        assertNull(
            shutdown.getHeader("Authorization"),
            "T-25-01: the squatter must receive no Authorization header at all",
        )

        // Asserted on the WHOLE serialised header block rather than on a named header on purpose: a
        // future edit could reintroduce the token under a different header name, and a named-header
        // assertion would not see it.
        val headerBlock = shutdown.headers.toString()
        assertFalse(
            headerBlock.contains(SQUATTER_TOKEN),
            "The MCP token must appear NOWHERE in the request the squatter received. Header block was:\n$headerBlock",
        )

        // Without these two the test could pass because no request was ever made, which would prove
        // nothing at all. They distinguish "sent something safe" from "sent nothing".
        val proof = shutdown.getHeader(McpTakeoverProof.HEADER)
        assertNotNull(proof, "The proof header must be present — the takeover must still be attempted, just safely")
        assertNotEquals(SQUATTER_TOKEN, proof, "The proof must not be the token wearing a different header name")
    }

    private companion object {
        /** Chosen to be unmistakable in a failure report if it ever shows up on the wire. */
        private const val SQUATTER_TOKEN = "squatter-must-never-see-this"
        private const val SHUTDOWN_PATH = "/__mcp/shutdown"
        private const val MAX_RECORDED_REQUESTS = 4
        private const val TAKE_REQUEST_TIMEOUT_SECONDS = 5L

        /**
         * Root-relative; resolved through [SourceRoots.file]. Covered by the production-root `inputs.dir`
         * declarations on `tasks.test` (first added in Phase 24 precisely so source-text assertions are
         * not served from a stale cache), so no redundant per-file declaration is added.
         */
        private const val SUPERVISOR_SOURCE = "com/six2dez/burp/aiagent/mcp/McpSupervisor.kt"
        private const val TOKEN_PROPERTY = "settings.token"
    }
}
