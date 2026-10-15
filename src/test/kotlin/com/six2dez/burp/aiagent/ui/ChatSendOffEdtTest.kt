package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.RecordingMontoya
import com.six2dez.burp.aiagent.backends.http.TestTransports
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import java.awt.event.ActionEvent
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JButton
import javax.swing.JEditorPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * Phase 33 / EDT-01 (SC5) — the chat-send health check runs off the EDT.
 *
 * Before this phase `ChatPanel.sendMessage` ran the Ollama / LM Studio readiness probe on the EDT. The
 * probe reaches `MontoyaHttpTransport.execute`, which, on the EDT, offloads the request to
 * `burp-ai-agent-http-offedt` and then blocks the EDT on the result: Burp's UI froze for as long as the
 * local service took to answer. These cases drive the REAL panel through [ChatPanelTestHarness] and
 * observe the probe where it runs, including the thread Burp's HTTP stack was entered on.
 *
 * The Phase 31 D-08/D-09 triggers are unchanged: only Ollama and LM Studio are probed, and the "start
 * it now?" prompt (here [LocalServiceReadiness]'s `onUnreachable`) stays on the EDT.
 *
 * **Naming constraint.** The class name must not end in one of the suffixes `-PexcludeHeavyTests`
 * drops (`IntegrationTest`, `ConcurrencyTest`, ...), or the PR gate stops running it.
 */
class ChatSendOffEdtTest {
    private val recording = RecordingMontoya()

    /** Threads Burp's (mocked) HTTP stack was entered on, in order. */
    private val requestThreads = CopyOnWriteArrayList<Thread>()

    @BeforeEach
    fun setUp() {
        ChatPanelTestHarness.installSettledObserver()
        recording.responder = { _ ->
            requestThreads.add(Thread.currentThread())
            200 to "{}"
        }
    }

    @AfterEach
    fun tearDown() {
        ChatPanelTestHarness.releaseSettledObserver()
        recording.close()
    }

    @Test
    fun anOllamaSendProbesOnTheNamedReadinessWorkerAndSendsOnlyAfterTheProbeReturned() {
        val harnessRef = AtomicReference<ChatPanelTestHarness.Harness>()
        val probeThreads = CopyOnWriteArrayList<Thread>()
        val probeRanOnEdt = CopyOnWriteArrayList<Boolean>()
        val sentWhenProbeReturned = AtomicInteger(-1)
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ ->
                    probeThreads.add(Thread.currentThread())
                    probeRanOnEdt.add(SwingUtilities.isEventDispatchThread())
                    val health = TestTransports.open(recording.api, OLLAMA).healthCheckGet(OLLAMA_TAGS_URL, emptyMap())
                    sentWhenProbeReturned.set(harnessRef.get().sentTraceIds.size)
                    health
                },
                onProbed = { },
                onUnreachable = { false },
            )
        val h = harness(OLLAMA, readiness).also(harnessRef::set)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        awaitReadinessSettled()

        val probeThread = probeThreads.single()
        assertEquals(READINESS_THREAD, probeThread.name, "the probe must run on the named readiness worker")
        assertTrue(probeThread.isDaemon, "the readiness worker must be a daemon so it cannot hold unload open")
        assertEquals(listOf(false), probeRanOnEdt.toList(), "the probe must never run on the EDT")
        assertEquals(1, recording.sendCount(), "the probe performs exactly one loopback request")
        assertSame(probeThread, requestThreads.single(), "Burp's HTTP stack must be entered on the readiness worker itself")
        assertTrue(
            requestThreads.none { it.name == OFFEDT_THREAD } && Thread.getAllStackTraces().keys.none { it.name == OFFEDT_THREAD },
            "the transport must never need its EDT offload thread for the chat-send probe",
        )
        assertEquals(0, sentWhenProbeReturned.get(), "no turn may be sent before the probe answered")
        assertEquals(1, h.sentTraceIds.size, "exactly one turn is sent once the probe answered")
        verifySendChatCount(h, 1)
        assertIdle(h)
    }

    @Test
    fun anUnreachableBackendTheUserDeclinesToStartSendsNothingAndAsksOnTheEdt() {
        val askedOnEdt = CopyOnWriteArrayList<Boolean>()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ -> HealthCheckResult.Unavailable("down") },
                onProbed = { },
                onUnreachable = { _ ->
                    askedOnEdt.add(SwingUtilities.isEventDispatchThread())
                    false
                },
            )
        val h = harness(OLLAMA, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        awaitReadinessSettled()

        assertEquals(listOf(true), askedOnEdt.toList(), "the start-it-now prompt is asked once, on the EDT")
        assertTrue(h.sentTraceIds.isEmpty(), "a declined start must send nothing")
        verifySendChatCount(h, 0)
        assertIdle(h)
    }

    @Test
    fun anUnreachableBackendTheUserStartsSendsTheTurnOnce() {
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ -> HealthCheckResult.Unavailable("down") },
                onProbed = { },
                onUnreachable = { _ -> true },
            )
        val h = harness(LMSTUDIO, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        awaitReadinessSettled()

        assertEquals(1, h.sentTraceIds.size)
        verifySendChatCount(h, 1)
    }

    @Test
    fun aThrowingProbeBecomesUnavailableAndSendsNothingWhenTheUserDeclines() {
        val asked = AtomicInteger()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ -> throw IllegalStateException("probe exploded") },
                onProbed = { },
                onUnreachable = { _ ->
                    asked.incrementAndGet()
                    false
                },
            )
        val h = harness(OLLAMA, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        awaitReadinessSettled()

        assertEquals(1, asked.get(), "a failed probe must still reach the start-it-now decision")
        assertTrue(h.sentTraceIds.isEmpty())
        verifySendChatCount(h, 0)
        assertIdle(h)
    }

    @Test
    fun aSecondSendClickOrEnterDuringTheProbeStartsNothing() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val probes = AtomicInteger()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ ->
                    probes.incrementAndGet()
                    entered.countDown()
                    release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
                    HealthCheckResult.Healthy
                },
                onProbed = { },
                onUnreachable = { false },
            )
        val h = harness(OLLAMA, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "first")
        assertTrue(entered.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the probe never started")

        SwingUtilities.invokeAndWait {
            assertFalse(sendButton(h).isVisible, "Send is hidden while the probe runs")
            assertFalse(inputArea(h).isEnabled, "the input is disabled while the probe runs")
        }
        // A second click on the (hidden) Send button, with new text in the input...
        ChatPanelTestHarness.sendUserMessage(h, "second click")
        // ...and a second Enter through the input's own key binding.
        SwingUtilities.invokeAndWait {
            val input = inputArea(h)
            input.text = "second enter"
            input.actionMap.get("sendMessage").actionPerformed(ActionEvent(input, ActionEvent.ACTION_PERFORMED, "enter"))
        }

        release.countDown()
        awaitReadinessSettled()

        assertEquals(1, probes.get(), "exactly one probe")
        assertEquals(1, h.sentTraceIds.size, "exactly one turn")
        verifySendChatCount(h, 1)
        val transcript = transcriptText(h)
        assertFalse(transcript.contains("second click"), "the blocked click must not reach the transcript: $transcript")
        assertFalse(transcript.contains("second enter"), "the blocked Enter must not reach the transcript: $transcript")
    }

    @Test
    fun cancelDuringTheProbeDropsItsAnswerAndSendsNothing() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val asked = AtomicInteger()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ ->
                    entered.countDown()
                    release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
                    HealthCheckResult.Healthy
                },
                onProbed = { },
                onUnreachable = { _ ->
                    asked.incrementAndGet()
                    true
                },
            )
        val h = harness(OLLAMA, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        assertTrue(entered.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the probe never started")
        val cancelled = AtomicReference<Boolean>()
        SwingUtilities.invokeAndWait { cancelled.set(h.panel.cancelInFlightRequest()) }
        assertEquals(true, cancelled.get(), "Cancel must act on an in-flight probe, not be a silent no-op")
        SwingUtilities.invokeAndWait {
            assertTrue(sendButton(h).isVisible, "Cancel returns the panel to idle at once")
            assertTrue(inputArea(h).isEnabled, "the input is usable again at once")
        }

        release.countDown()
        awaitReadinessSettled()

        assertTrue(h.sentTraceIds.isEmpty(), "a cancelled probe's answer must not send the turn")
        verifySendChatCount(h, 0)
        assertEquals(0, asked.get())
        assertTrue(transcriptText(h).contains("Request cancelled."))
        assertIdle(h)
    }

    @Test
    fun aNonLocalBackendSendsWithNoProbeAndNoThreadHop() {
        val probes = AtomicInteger()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ ->
                    probes.incrementAndGet()
                    HealthCheckResult.Healthy
                },
                onProbed = { },
                onUnreachable = { false },
            )
        val h = harness(OPENAI_COMPATIBLE, readiness)

        ChatPanelTestHarness.sendUserMessage(h, "hello")
        ChatPanelTestHarness.drainEdt()

        assertEquals(0, probes.get(), "only Ollama and LM Studio are probed before a send")
        assertTrue(
            ChatPanelTestHarness.dispatchedLabels().none { it.startsWith(READINESS_LABEL_PREFIX) },
            "no readiness worker may be dispatched for a non-local backend",
        )
        assertTrue(Thread.getAllStackTraces().keys.none { it.name == READINESS_THREAD })
        assertEquals(1, h.sentTraceIds.size)
        verifySendChatCount(h, 1)
    }

    @Test
    fun localServiceReadinessProbesOnlyOllamaAndLmStudioAndAsksOnlyWhenUnreachable() {
        val probed = CopyOnWriteArrayList<HealthCheckResult>()
        val asked = AtomicInteger()
        val readiness =
            LocalServiceReadiness(
                backendHealth = { _ -> HealthCheckResult.Degraded("slow") },
                onProbed = { probed.add(it) },
                onUnreachable = { _ ->
                    asked.incrementAndGet()
                    false
                },
            )

        assertTrue(readiness.needsProbe(TestSettings.baselineSettings(OLLAMA)))
        assertTrue(readiness.needsProbe(TestSettings.baselineSettings(LMSTUDIO)))
        listOf(OPENAI_COMPATIBLE, "codex-cli", "anthropic", "burp-ai").forEach { id ->
            assertFalse(readiness.needsProbe(TestSettings.baselineSettings(id)), "$id must not be probed")
        }

        val settings = TestSettings.baselineSettings(OLLAMA)
        assertEquals(HealthCheckResult.Degraded("slow"), readiness.probe(settings))
        assertEquals(listOf<HealthCheckResult>(HealthCheckResult.Degraded("slow")), probed.toList(), "the probe result is painted")
        assertTrue(readiness.confirm(settings, HealthCheckResult.Healthy))
        assertTrue(readiness.confirm(settings, HealthCheckResult.Degraded("slow")))
        assertEquals(0, asked.get(), "a reachable backend never asks to start the service")
        assertFalse(readiness.confirm(settings, HealthCheckResult.Unavailable("down")))
        assertEquals(1, asked.get())

        val always = ChatBackendReadiness.ALWAYS_READY
        assertFalse(always.needsProbe(settings))
        assertTrue(always.confirm(settings, HealthCheckResult.Unavailable("down")))
    }

    private fun harness(
        backendId: String,
        readiness: ChatBackendReadiness,
    ): ChatPanelTestHarness.Harness =
        ChatPanelTestHarness.create(
            modelResponse = "ok",
            settings = TestSettings.baselineSettings(backendId),
            readiness = readiness,
        )

    /** Waits until the one readiness worker this test dispatched has run its EDT tail. */
    private fun awaitReadinessSettled() {
        val labels = ChatPanelTestHarness.dispatchedLabels().filter { it.startsWith(READINESS_LABEL_PREFIX) }
        assertEquals(1, labels.size, "expected exactly one readiness dispatch; dispatched: ${ChatPanelTestHarness.dispatchedLabels()}")
        ChatPanelTestHarness.awaitToolSettled(label = labels.single(), count = 1)
    }

    private fun assertIdle(h: ChatPanelTestHarness.Harness) {
        SwingUtilities.invokeAndWait {
            assertTrue(sendButton(h).isVisible, "Send is visible again once the send settled")
            assertTrue(inputArea(h).isEnabled, "the input is enabled again once the send settled")
        }
    }

    private fun sendButton(h: ChatPanelTestHarness.Harness): JButton =
        requireNotNull(ChatPanelTestHarness.find(h.panel.root, JButton::class.java) { it.text == "Send" })

    private fun inputArea(h: ChatPanelTestHarness.Harness): JTextArea = ChatPanelTestHarness.inputTextArea(h)

    private fun transcriptText(h: ChatPanelTestHarness.Harness): String {
        val ref = AtomicReference("")
        SwingUtilities.invokeAndWait {
            ref.set(
                ChatPanelTestHarness
                    .findAll(h.panel.root, JEditorPane::class.java)
                    .joinToString(" ") { pane -> pane.document.getText(0, pane.document.length) },
            )
        }
        return ref.get()
    }

    private fun verifySendChatCount(
        h: ChatPanelTestHarness.Harness,
        expected: Int,
    ) {
        verify(h.supervisor, times(expected)).sendChat(
            any(),
            any(),
            any(),
            anyOrNull(),
            anyOrNull(),
            any(),
            any(),
            any(),
            any(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
            anyOrNull(),
        )
    }

    private companion object {
        const val OLLAMA = "ollama"
        const val LMSTUDIO = "lmstudio"
        const val OPENAI_COMPATIBLE = "openai-compatible"
        const val OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
        const val READINESS_THREAD = "burp-ai-agent-chat-readiness"
        const val READINESS_LABEL_PREFIX = "chat readiness "
        const val OFFEDT_THREAD = "burp-ai-agent-http-offedt"
        const val FAILSAFE_SECONDS = 10L
    }
}
