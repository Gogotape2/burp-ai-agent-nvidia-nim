package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.burpai.BurpAiBackend
import com.six2dez.burp.aiagent.config.AgentSettings
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import java.time.LocalTime
import java.util.ArrayDeque
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicInteger

/** Headless pure-logic tests for the status-pill scheduling (quick 261008-kw4). */
class BackendHealthSchedulingTest {
    private fun settings(
        backendId: String,
        transform: (AgentSettings) -> AgentSettings = { it },
    ): AgentSettings = transform(TestSettings.baselineSettings(preferredBackendId = backendId))

    /** A backend whose health check is a local probe; core names no id for it (D-09). */
    private val localProbe = probeBackend(id = "some-external-local-probe", local = true)

    /** A drop-in backend that does not declare a local health check. */
    private val externalRemote = probeBackend(id = "some-external-backend", local = false)

    private val burpAi = BurpAiBackend(mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS))

    private fun probeBackend(
        id: String,
        local: Boolean,
    ): AiBackend =
        object : AiBackend {
            override val id: String = id
            override val displayName: String = id
            override val healthCheckIsLocal: Boolean = local

            override fun launch(config: BackendLaunchConfig): AgentConnection = throw UnsupportedOperationException()
        }

    @Test
    fun aBackendThatDeclaresALocalHealthCheckIsLocal() {
        assertTrue(burpAi.healthCheckIsLocal, "Burp AI's health check never leaves Burp")
        assertTrue(BackendHealthPolicy.isLocal(settings("burp-ai"), burpAi))
        assertTrue(BackendHealthPolicy.isLocal(settings(localProbe.id), localProbe))
        assertFalse(BackendHealthPolicy.isLocal(settings(externalRemote.id), externalRemote))
        assertFalse(BackendHealthPolicy.isLocal(settings("burp-ai"), null), "no backend, no local claim")
    }

    @Test
    fun periodicRunsOnlyForLocalBackends() {
        val local =
            listOf(
                settings("burp-ai") to burpAi,
                settings(localProbe.id) to localProbe,
                settings("ollama") { it.copy(ollamaUrl = "http://127.0.0.1:11434") } to null,
                settings("ollama") { it.copy(ollamaUrl = "") } to null,
                settings("lmstudio") { it.copy(lmStudioUrl = "http://localhost:1234") } to null,
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "http://127.0.0.1:8080/v1") } to null,
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "http://[::1]:8000") } to null,
            )
        local.forEach { (s, backend) ->
            assertTrue(
                BackendHealthPolicy.shouldRun(HealthCheckTrigger.PERIODIC, s, backend),
                "expected periodic poll for ${s.preferredBackendId}",
            )
        }
    }

    @Test
    fun periodicNeverRunsForRemoteOrUnknownBackends() {
        val remote =
            listOf(
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "https://integrate.api.nvidia.com") } to null,
                settings("nvidia-nim") { it.copy(nvidiaNimUrl = "") } to null,
                settings("perplexity") { it.copy(perplexityUrl = "https://api.perplexity.ai") } to null,
                settings("perplexity") { it.copy(perplexityUrl = "") } to null,
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "https://api.openai.com/v1") } to null,
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "http://192.168.1.50:8000") } to null,
                settings("openai-compatible") { it.copy(openAiCompatibleUrl = "") } to null,
                settings("anthropic") to null,
                settings(externalRemote.id) to externalRemote,
                settings("some-unregistered-backend") to null,
            )
        remote.forEach { (s, backend) ->
            assertFalse(
                BackendHealthPolicy.shouldRun(HealthCheckTrigger.PERIODIC, s, backend),
                "a timer must never poll ${s.preferredBackendId}",
            )
        }
    }

    @Test
    fun onDemandTriggersAlwaysRun() {
        val remote = settings("perplexity") { it.copy(perplexityUrl = "https://api.perplexity.ai") }
        val unknown = settings(externalRemote.id)
        listOf(HealthCheckTrigger.STARTUP, HealthCheckTrigger.SETTINGS_CHANGED, HealthCheckTrigger.USER_CLICK).forEach { trigger ->
            assertTrue(BackendHealthPolicy.shouldRun(trigger, remote, null))
            assertTrue(BackendHealthPolicy.shouldRun(trigger, unknown, externalRemote))
        }
    }

    @Test
    fun tooltipShowsTheLastCheckTime() {
        assertEquals(
            "Backend health check passed. Last checked 09:05:07. Click to re-check.",
            BackendHealthPolicy.tooltip("Backend health check passed.", LocalTime.of(9, 5, 7)),
        )
    }

    /** Executor that queues runnables until the test drains them. */
    private class ManualExecutor : Executor {
        val queue = ArrayDeque<Runnable>()

        override fun execute(command: Runnable) {
            queue.add(command)
        }

        fun runNext() = queue.removeFirst().run()
    }

    @Test
    fun singleFlightRejectsASecondSubmitWhileBusy() {
        val exec = ManualExecutor()
        val gate = SingleFlightGate(exec) {}
        assertTrue(gate.submit(coalesce = false) {})
        assertEquals(1, exec.queue.size)
        assertFalse(gate.submit(coalesce = false) {})
        assertEquals(1, exec.queue.size, "a busy gate must not enqueue")
        exec.runNext()
        assertTrue(gate.submit(coalesce = false) {}, "the gate must reopen after the flight")
        assertEquals(1, exec.queue.size)
    }

    @Test
    fun coalescingSubmitsDuringAFlightTriggerExactlyOneRerun() {
        val exec = ManualExecutor()
        val reruns = AtomicInteger(0)
        val gate = SingleFlightGate(exec) { reruns.incrementAndGet() }
        assertTrue(gate.submit(coalesce = true) {})
        assertFalse(gate.submit(coalesce = true) {})
        assertFalse(gate.submit(coalesce = true) {})
        assertEquals(0, reruns.get())
        exec.runNext()
        assertEquals(1, reruns.get())
    }

    @Test
    fun nonCoalescingSubmitDuringAFlightTriggersNoRerun() {
        val exec = ManualExecutor()
        val reruns = AtomicInteger(0)
        val gate = SingleFlightGate(exec) { reruns.incrementAndGet() }
        assertTrue(gate.submit(coalesce = false) {})
        assertFalse(gate.submit(coalesce = false) {})
        exec.runNext()
        assertEquals(0, reruns.get())
    }

    @Test
    fun aThrowingTaskStillReleasesTheGate() {
        val exec = ManualExecutor()
        val gate = SingleFlightGate(exec) {}
        assertTrue(gate.submit(coalesce = false) { error("boom") })
        runCatching { exec.runNext() }
        assertTrue(gate.submit(coalesce = false) {}, "a failed check must not wedge the pill")
    }

    @Test
    fun rejectedExecutionLeavesTheGateReleased() {
        // A second submit must reach the executor again (and be rejected again) instead of being
        // refused as "busy" without trying: the rejection released the gate.
        val attempts = AtomicInteger(0)
        val gate =
            SingleFlightGate(
                Executor {
                    attempts.incrementAndGet()
                    throw RejectedExecutionException("shut down")
                },
            ) {}
        assertFalse(gate.submit(coalesce = false) {})
        assertFalse(gate.submit(coalesce = false) {})
        assertEquals(2, attempts.get(), "a rejected submit must leave the gate released")
    }
}
