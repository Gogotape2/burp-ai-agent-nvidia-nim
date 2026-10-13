package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.lmstudio.LmStudioBackend
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Phase 31 / GATE-01 — the egress choke point in isolation: `MontoyaHttpTransport.execute` asks the
 * gate first, on every request, and every way of reaching it without an allowing, bound gate fails
 * closed (refused, unbound, gate-less, on the EDT, repeated). A refusal is a policy outcome, so it is
 * never retried and never counted by the circuit breaker (RESEARCH Pitfall 3).
 */
class MontoyaHttpTransportEgressTest {
    private val recording = RecordingMontoya()

    @AfterEach
    fun tearDown() {
        recording.close()
    }

    @Test
    fun aRefusingBoundTransportRefusesPostGetAndHealthCheckWithoutSending() {
        val transport = TestTransports.refusing(recording.api, REFUSAL, "lmstudio")

        assertRefused(REFUSAL) { transport.post(URL, emptyMap(), "{}") }
        assertRefused(REFUSAL) { transport.get(URL, emptyMap()) }
        assertEquals(HealthCheckResult.Unavailable(REFUSAL), transport.healthCheckGet(URL, emptyMap()))
        assertEquals(0, recording.sendCount(), "a refused request never reaches Http.sendRequest")
    }

    @Test
    fun theUnboundRootAndTheGateLessTransportRefuseEveryRequest() {
        val root = MontoyaHttpTransport(recording.api, TestTransports.ALLOW_ALL)
        assertNull(root.boundBackendId)
        assertRefused(MontoyaHttpTransport.UNBOUND_REFUSAL) { root.post(URL, emptyMap(), "{}") }

        // requireEgress checks the binding first, so the unbound gate-less transport reports that;
        // once bound, its gate refuses: it can never let a request through either way.
        val gateLess = MontoyaHttpTransport(recording.api)
        assertRefused(MontoyaHttpTransport.UNBOUND_REFUSAL) { gateLess.post(URL, emptyMap(), "{}") }
        assertRefused(MontoyaHttpTransport.NO_GATE_REFUSAL) { gateLess.forBackend("lmstudio").post(URL, emptyMap(), "{}") }

        assertEquals(0, recording.sendCount())
    }

    @Test
    fun aRefusedPostOnTheEdtThrowsThereAndStartsNoOffloadThread() {
        val transport = TestTransports.refusing(recording.api, REFUSAL, "lmstudio")
        val thrown = AtomicReference<Throwable?>()
        val onEdt = AtomicBoolean(false)

        SwingUtilities.invokeAndWait {
            onEdt.set(SwingUtilities.isEventDispatchThread())
            try {
                transport.post(URL, emptyMap(), "{}")
            } catch (e: AiAccessRefusedException) {
                thrown.set(e)
            }
        }

        assertTrue(onEdt.get(), "the post must run on the EDT for this test to mean anything")
        assertEquals(REFUSAL, thrown.get()?.message)
        val offload = Thread.getAllStackTraces().keys.filter { it.name == "montoya-http-offedt" && it.isAlive }
        assertTrue(offload.isEmpty(), "a refused request must start no off-EDT worker, found $offload")
        assertEquals(0, recording.sendCount())
    }

    @Test
    fun forBackendTwiceGivesTwoViewsBoundToTheSameIdOverTheSameGate() {
        val askedFor = CopyOnWriteArrayList<String>()
        val root =
            MontoyaHttpTransport(recording.api) { backendId ->
                askedFor += backendId
                REFUSAL
            }

        val first = root.forBackend("x")
        val second = root.forBackend("x")

        assertNotSame(first, second)
        assertEquals("x", first.boundBackendId)
        assertEquals("x", second.boundBackendId)
        assertRefused(REFUSAL) { first.post(URL, emptyMap(), "{}") }
        assertRefused(REFUSAL) { second.post(URL, emptyMap(), "{}") }
        assertEquals(listOf("x", "x"), askedFor.toList(), "both views ask the one shared gate, once per request")
        assertEquals(0, recording.sendCount())
    }

    @Test
    fun anAllowedBoundTransportSendsOnceWithUpstreamTls() {
        val response = TestTransports.open(recording.api, "lmstudio").post(URL, emptyMap(), "{}")

        assertEquals(200, response.statusCode)
        assertEquals(1, recording.sendCount())
        verify(recording.options, times(1)).withUpstreamTLSVerification()
    }

    @Test
    fun aRefusalIsNeverRetryableWhateverItsMessageSays() {
        assertFalse(HttpBackendSupport.isRetryableConnectionError(AiAccessRefusedException(RETRY_LOOKING_REFUSAL)))
    }

    @Test
    fun sixRefusedSendsGiveSixRefusalsAndNeverOpenTheCircuitBreaker() {
        val connection =
            LmStudioBackend().launch(
                BackendLaunchConfig(
                    backendId = "lmstudio",
                    displayName = "LM Studio",
                    baseUrl = "http://127.0.0.1:1234",
                    model = "local-model",
                    headers = emptyMap(),
                    requestTimeoutSeconds = 30L,
                    transport = TestTransports.refusing(recording.api, RETRY_LOOKING_REFUSAL, "lmstudio"),
                ),
            )
        try {
            val errors = (1..6).map { sendAndAwait(connection) }

            errors.forEach { error ->
                assertTrue(error is AiAccessRefusedException, "expected a refusal, got ${errors.map { it?.message }}")
                assertEquals(RETRY_LOOKING_REFUSAL, error?.message)
            }
            assertFalse(errors.any { it?.message?.contains("circuit open") == true }, "a refusal must never trip the breaker")
            assertEquals(0, recording.sendCount())
        } finally {
            connection.stop()
        }
    }

    private fun assertRefused(
        expected: String,
        block: () -> Unit,
    ) {
        val thrown = assertThrows(AiAccessRefusedException::class.java) { block() }
        assertEquals(expected, thrown.message)
    }

    private fun sendAndAwait(connection: AgentConnection): Throwable? {
        val error = AtomicReference<Throwable?>()
        val done = CountDownLatch(1)
        connection.send(
            text = "test",
            onChunk = {},
            onComplete = { err ->
                error.set(err)
                done.countDown()
            },
            jsonMode = false,
        )
        assertTrue(done.await(AWAIT_SECONDS, TimeUnit.SECONDS), "send() did not complete within ${AWAIT_SECONDS}s")
        return error.get()
    }

    private companion object {
        const val URL = "http://127.0.0.1:1234/v1/chat/completions"
        const val REFUSAL = "refused by the test gate"

        // Worded so the message-substring retry test would match it: only the type check saves it.
        const val RETRY_LOOKING_REFUSAL = "connection refused timeout"
        const val AWAIT_SECONDS = 20L
    }
}
