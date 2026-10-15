package com.six2dez.burp.aiagent.lifecycle

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import com.six2dez.burp.aiagent.App
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveScannerRig
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 / CR-01, LIFE-02 ("Unload sends no AI traffic") — an unload that begins while the AI is
 * answering stops that answer at once and lets nothing the extension does afterwards reach a provider.
 *
 * CR-01 was the gap: App.shutdown's first step left the chat live. AgentSupervisor had no unload latch,
 * so during the MCP and scanner steps (which can take seconds) the chat could still start provider
 * requests, and a session's first-turn connection, which ChatSessionManager only learns about on
 * completion, was stopped only by the final thread sweep.
 *
 * Here a Burp AI chat turn, the first of its chat session, is blocked inside `prompt().execute` when
 * [App.shutdown] runs. Its completion callback then issues a second `sendChat` in the same session: that
 * is how the chat's automatic tool chain fires its next turn, from the completion of the previous one.
 * The unload's first step must stop the blocked turn (the execute sees an interrupt), the continuation
 * must be refused with [AgentSupervisor.UNLOADING_REFUSAL] without reaching `execute`, and the unload
 * stays silent (no `Unload:` and no `AI backend error` Error line) and leaves no extension thread.
 *
 * Package `lifecycle`: runs only in the `unloadLeakTest` task, one JVM per class.
 */
class UnloadMidTurnProbe {
    @TempDir
    lateinit var profileHome: Path

    private val rigs = CopyOnWriteArrayList<ActiveScannerRig>()
    private val release = CountDownLatch(1)

    @BeforeEach
    fun isolate() {
        AgentProfileLoader.setBaseDirForTests(profileHome)
    }

    @AfterEach
    fun restore() {
        release.countDown()
        rigs.forEach { runCatching { it.close() } }
        AgentProfileLoader.setBaseDirForTests(null)
    }

    @Test
    fun unloadMidTurnStopsTheTurnAtStepZeroAndRefusesItsContinuation() {
        val threadsBefore = liveThreads()
        val blocking = BlockingPrompt(release)
        val session = newSession(blocking.prompt)
        App.initialize(session.api)

        val firstError = AtomicReference<Throwable?>()
        val continuationError = AtomicReference<Throwable?>()
        val continuationDone = CountDownLatch(1)
        App.supervisor.sendChat(
            chatSessionId = CHAT_SESSION,
            backendId = BURP_AI,
            text = "first turn",
            contextJson = null,
            privacyMode = PrivacyMode.BALANCED,
            determinismMode = false,
            onChunk = {},
            onComplete = { error ->
                firstError.set(error)
                // The tool chain's next turn, issued from the completion of the previous one.
                chat("tool-chain continuation") { next ->
                    continuationError.set(next)
                    continuationDone.countDown()
                }
            },
        )
        assertTrue(blocking.inFlight.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "the first turn never reached execute")

        val errorsBeforeUnload = session.errors.size
        assertTimeoutPreemptively(Duration.ofSeconds(UNLOAD_SECONDS), "the unload must fit its bound") {
            App.shutdown(shutdownSharedCoroutines = false)
        }

        assertTrue(continuationDone.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "the stopped turn never completed")
        assertTrue(blocking.interrupted.get(), "the unload must stop the turn in flight (execute sees an interrupt)")
        assertNotNull(firstError.get(), "the stopped turn completes with an error")
        assertUnloadingRefusal(continuationError.get(), "the tool-chain continuation")
        assertEquals(1, blocking.executions.get(), "Burp AI's execute must run exactly once")

        val afterUnload = AtomicReference<Throwable?>()
        val afterDone = CountDownLatch(1)
        chat("after unload") { error ->
            afterUnload.set(error)
            afterDone.countDown()
        }
        assertTrue(afterDone.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "a chat after unload must complete at once")
        assertUnloadingRefusal(afterUnload.get(), "a chat after unload")
        assertEquals(1, blocking.executions.get(), "nothing after unload reaches execute")

        val unloadErrors = session.errors.drop(errorsBeforeUnload)
        assertTrue(unloadErrors.none { it.startsWith("Unload:") }, "the turn is stopped at step 0, not forced by the sweep: $unloadErrors")
        assertTrue(unloadErrors.none { it.contains("AI backend error") }, "a turn the unload stopped is not an error: $unloadErrors")

        val leaked = pollForLeaks(threadsBefore)
        assertTrue(leaked.isEmpty(), "extension threads outlive the unload: ${leaked.joinToString { it.name }}")
    }

    private fun chat(
        text: String,
        onComplete: (Throwable?) -> Unit,
    ) {
        App.supervisor.sendChat(
            chatSessionId = CHAT_SESSION,
            backendId = BURP_AI,
            text = text,
            contextJson = null,
            privacyMode = PrivacyMode.BALANCED,
            determinismMode = false,
            onChunk = {},
            onComplete = onComplete,
        )
    }

    private fun assertUnloadingRefusal(
        error: Throwable?,
        what: String,
    ) {
        assertTrue(error is AiAccessRefusedException, "$what must be refused, got $error")
        assertEquals(AgentSupervisor.UNLOADING_REFUSAL, error?.message, "$what must carry the unloading refusal")
    }

    private class Session(
        val api: MontoyaApi,
        val errors: MutableList<String>,
    )

    /** UnloadLeakProbe's session shape: in-memory preferences, Error lines captured, Burp AI enabled. */
    private fun newSession(prompt: Prompt): Session {
        val rig = ActiveScannerRig().also { rigs += it }
        val api = rig.api
        whenever(api.persistence().preferences()).thenReturn(InMemoryPreferences())
        val errors = CopyOnWriteArrayList<String>()
        // Read before doAnswer: a deep-stub call inside the stubbing chain is an unfinished stubbing.
        val logging = api.logging()
        doAnswer { invocation ->
            errors += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyString())
        val ai = api.ai()
        whenever(ai.isEnabled).thenReturn(true)
        whenever(ai.prompt()).thenReturn(prompt)
        return Session(api, errors)
    }

    /**
     * A Burp AI prompt whose first `execute` blocks until [release] (failsafe [BLOCK_SECONDS]) and records
     * an interrupt; later calls answer at once.
     */
    private class BlockingPrompt(
        release: CountDownLatch,
    ) {
        val inFlight = CountDownLatch(1)
        val interrupted = AtomicBoolean(false)
        val executions = AtomicInteger(0)
        private val response =
            Mockito.mock(PromptResponse::class.java).also { whenever(it.content()).thenReturn(ANSWER) }

        val prompt: Prompt =
            Mockito.mock(
                Prompt::class.java,
                Answer { invocation ->
                    if (invocation.method.name != "execute") return@Answer Answers.RETURNS_DEFAULTS.answer(invocation)
                    if (executions.incrementAndGet() == 1) {
                        inFlight.countDown()
                        try {
                            release.await(BLOCK_SECONDS, TimeUnit.SECONDS)
                        } catch (e: InterruptedException) {
                            interrupted.set(true)
                            throw IllegalStateException("execute interrupted", e)
                        }
                    }
                    response
                },
            )
    }

    private fun liveThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive }
            .toSet()

    /** New `burp-ai-agent-*` threads (absent from [before]), polled for up to 5 s until none. */
    private fun pollForLeaks(before: Set<Thread>): List<Thread> {
        val probe = { (liveThreads() - before).filter { it.name.startsWith(PREFIX) } }
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(LEAK_POLL_SECONDS)
        while (System.nanoTime() < end) {
            if (probe().isEmpty()) return emptyList()
            Thread.sleep(POLL_MS)
        }
        return probe()
    }

    private companion object {
        const val PREFIX = "burp-ai-agent-"
        const val CHAT_SESSION = "unload-mid-turn-probe"
        const val BURP_AI = "burp-ai"
        const val ANSWER = "unload-mid-turn-probe answer"
        const val UNLOAD_SECONDS = 12L
        const val ACTIVITY_SECONDS = 10L
        const val BLOCK_SECONDS = 20L
        const val LEAK_POLL_SECONDS = 5L
        const val POLL_MS = 50L
    }
}
