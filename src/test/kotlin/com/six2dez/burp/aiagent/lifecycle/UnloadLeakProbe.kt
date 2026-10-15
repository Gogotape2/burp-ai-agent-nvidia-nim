package com.six2dez.burp.aiagent.lifecycle

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ai.chat.Prompt
import burp.api.montoya.ai.chat.PromptResponse
import burp.api.montoya.extension.ExtensionUnloadingHandler
import com.six2dez.burp.aiagent.App
import com.six2dez.burp.aiagent.BurpAiAgentExtension
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.toPreprocessorSettings
import com.six2dez.burp.aiagent.mcp.KtorMcpServerManager
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.ActiveScannerRig
import com.six2dez.burp.aiagent.scanner.ScanMode
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.ByteArrayOutputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Phase 33 / D-13(a), LIFE-01 / SC1 — the automated leak proof: a real session through [App] against a
 * deep-stubbed MontoyaApi, then an unload, and nothing the extension started is left running.
 *
 * The session is the one a user has: a chat turn on Burp AI, the active scanner switched on, fed a target
 * and switched off again, a passive manual scan, and the MCP server started on port 0 with an SSE session
 * held open across the unload. Before the unload, the probe asserts that each of these really happened,
 * so a session that silently did nothing cannot pass (T-33-31).
 *
 * **What counts as a leak.** A thread that was not alive in the snapshot taken before the load and whose
 * name is one of the extension's (`burp-ai-agent-*`) or one an unnamed thread or pool would get
 * (`Thread-N`, `pool-N-thread-M`), or Netty's event loops under Ktor (`eventLoopGroupProxy-*`). Library
 * housekeeping threads (Netty's `globalEventExecutor`, kotlinx's `DefaultExecutor`) end on their own
 * about 1 s after the last task, so the check is a bounded 5 s poll, not an immediate snapshot (RESEARCH
 * Pitfall 6). Every port the MCP server bound must refuse a connection, and no `Unload:` Error line
 * (a forced or late component, D-09) may be written.
 *
 * **Shared coroutines.** The App path passes `shutdownSharedCoroutines = false`, so kotlinx's parked
 * `DefaultDispatcher-worker-*` threads are allowed there. The production path, through the handler
 * [BurpAiAgentExtension] registers, runs the irreversible guarded `Dispatchers.shutdown()`, which is why
 * it is ordered LAST, and it must leave no `DefaultDispatcher-worker-*` thread (D-12).
 *
 * Package `lifecycle`: runs only in the `unloadLeakTest` task, one JVM per class.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class UnloadLeakProbe {
    @TempDir
    lateinit var profileHome: Path

    private val boundPorts = CopyOnWriteArrayList<Int>()
    private val rigs = CopyOnWriteArrayList<ActiveScannerRig>()
    private val sockets = CopyOnWriteArrayList<Socket>()

    @BeforeEach
    fun isolate() {
        AgentProfileLoader.setBaseDirForTests(profileHome)
        KtorMcpServerManager.onBoundForTests = { port -> boundPorts += port }
    }

    @AfterEach
    fun restore() {
        sockets.forEach { runCatching { it.close() } }
        rigs.forEach { runCatching { it.close() } }
        KtorMcpServerManager.onBoundForTests = null
        AgentProfileLoader.setBaseDirForTests(null)
    }

    /**
     * D-13(a) / SC1: load, chat, active scanner on-scan-off, passive manual scan, MCP with an open SSE
     * session, then [App.shutdown]: no new extension, pool, unnamed or Netty event-loop thread, no bound
     * port still listening, and no `Unload:` Error line.
     */
    @Test
    @Order(1)
    fun aFullSessionThenUnloadLeavesNoThreadNoListenerAndNoUnloadError() {
        val threadsBefore = liveThreads()
        val session = newSession()
        App.initialize(session.api)

        chatOnce()
        val sent = runActiveScannerOnScanOff(session.rig)
        runPassiveManualScan(session.rig)
        val port = startMcpOnPortZero(session.api)
        assertTrue(healthAnswers(port), "the MCP health route must answer on port $port")
        val sseBytes = openSseSession(port)

        // Non-vacuous: every activity happened, and extension threads were really alive before the unload.
        assertTrue(sent > 0, "the active scanner must have sent at least one request")
        assertTrue(sseBytes.isNotEmpty(), "the SSE session must have returned bytes")
        val extensionThreadsBeforeUnload = (liveThreads() - threadsBefore).filter { it.name.startsWith(PREFIX) }
        assertTrue(
            extensionThreadsBeforeUnload.isNotEmpty(),
            "the session must have started at least one $PREFIX thread, or the leak check proves nothing",
        )

        val errorsBeforeUnload = session.errors.size
        assertTimeoutPreemptively(Duration.ofSeconds(UNLOAD_SECONDS), "the unload must fit its bound") {
            App.shutdown(shutdownSharedCoroutines = false)
        }

        val leaked = pollForLeaks(threadsBefore, LEAK_PATTERNS)
        assertTrue(leaked.isEmpty(), "threads the session started outlive the unload: ${describe(leaked)}")
        boundPorts.forEach { bound -> assertFalse(isListening(bound), "MCP port $bound still accepts connections after unload") }
        val unloadErrors = session.errors.drop(errorsBeforeUnload)
        assertTrue(unloadErrors.none { it.startsWith("Unload:") }, "a clean unload forces nothing and misses no deadline: $unloadErrors")
        assertTrue(unloadErrors.none { it.contains("shutdown failed") }, "no unload step may fail: $unloadErrors")
    }

    /**
     * D-12 / SC1: the production unload path, the handler [BurpAiAgentExtension] registers, leaves no
     * `DefaultDispatcher-worker-*` and no new extension thread after a session that started MCP, and the
     * bound port refuses a connection. Ordered LAST: it runs the irreversible shared coroutine shutdown.
     */
    @Test
    @Order(LAST)
    fun theProductionUnloadHandlerAlsoClearsCoroutineWorkers() {
        val threadsBefore = liveThreads()
        val session = newSession()
        BurpAiAgentExtension().initialize(session.api)
        val handler = argumentCaptor<ExtensionUnloadingHandler>()
        verify(session.api.extension()).registerUnloadingHandler(handler.capture())

        val port = startMcpOnPortZero(session.api)
        assertTrue(healthAnswers(port), "the MCP health route must answer on port $port")
        assertTrue(
            liveThreads().any { it.name.startsWith(COROUTINE_WORKER) },
            "Ktor must have used a shared coroutine worker, or the check below proves nothing",
        )

        val errorsBeforeUnload = session.errors.size
        assertTimeoutPreemptively(Duration.ofSeconds(UNLOAD_SECONDS), "the production unload must fit its bound") {
            handler.firstValue.extensionUnloaded()
        }

        val workers = pollUntilEmpty { liveThreads().filter { it.name.startsWith(COROUTINE_WORKER) } }
        assertTrue(workers.isEmpty(), "coroutine workers outlive the production unload: ${describe(workers)}")
        val leaked = pollForLeaks(threadsBefore, listOf(Regex("$PREFIX.*")))
        assertTrue(leaked.isEmpty(), "extension threads outlive the production unload: ${describe(leaked)}")
        boundPorts.forEach { bound -> assertFalse(isListening(bound), "MCP port $bound still accepts connections after unload") }
        val unloadErrors = session.errors.drop(errorsBeforeUnload)
        assertTrue(unloadErrors.none { it.startsWith("Unload:") }, "the production unload forces nothing: $unloadErrors")
    }

    private class Session(
        val api: MontoyaApi,
        val rig: ActiveScannerRig,
        val errors: MutableList<String>,
    )

    /**
     * A deep-stubbed MontoyaApi whose HTTP stack answers every request (ActiveScannerRig), with in-memory
     * preferences (MCP off), Burp AI enabled and a prompt that answers, and Error lines captured.
     */
    private fun newSession(): Session {
        val rig = ActiveScannerRig().also { rigs += it }
        val api = rig.api
        val preferences = InMemoryPreferences()
        whenever(api.persistence().preferences()).thenReturn(preferences)
        val errors = CopyOnWriteArrayList<String>()
        // Read before doAnswer: a deep-stub call inside the stubbing chain is an unfinished stubbing.
        val logging = api.logging()
        doAnswer { invocation ->
            errors += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyString())
        val ai = api.ai()
        whenever(ai.isEnabled).thenReturn(true)
        val prompt = answeringPrompt()
        whenever(ai.prompt()).thenReturn(prompt)
        return Session(api, rig, errors)
    }

    private fun answeringPrompt(): Prompt {
        val response = Mockito.mock(PromptResponse::class.java)
        whenever(response.content()).thenReturn(CHAT_ANSWER)
        return Mockito.mock(
            Prompt::class.java,
            Answer { invocation ->
                if (invocation.method.name == "execute") response else Answers.RETURNS_DEFAULTS.answer(invocation)
            },
        )
    }

    /** One chat turn on Burp AI through the chat supervisor; asserts the answer arrived. */
    private fun chatOnce() {
        val done = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)
        val answer = StringBuffer()
        App.supervisor.sendChat(
            chatSessionId = "unload-leak-probe",
            backendId = "burp-ai",
            text = "hello",
            contextJson = null,
            privacyMode = PrivacyMode.BALANCED,
            determinismMode = false,
            onChunk = { answer.append(it) },
            onComplete = { error ->
                failure.set(error)
                done.countDown()
            },
        )
        assertTrue(done.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "the chat turn never completed")
        assertNull(failure.get(), "the chat turn failed: ${failure.get()}")
        assertTrue(answer.contains(CHAT_ANSWER), "the chat answer never arrived: '$answer'")
    }

    /** Active scanner on, one manual target, at least one request sent, then off; returns the send count. */
    private fun runActiveScannerOnScanOff(rig: ActiveScannerRig): Int {
        val scanner = App.activeAiScanner
        scanner.scopeOnly = false
        scanner.scanMode = ScanMode.FULL
        scanner.requestDelayMs = 0
        scanner.maxPayloadsPerPoint = 1
        scanner.useCollaborator = false
        scanner.setEnabled(true)
        val queued = scanner.manualScan(listOf(rig.requestResponse()))
        assertTrue(queued > 0, "the manual active scan must queue at least one target")
        assertTrue(pollUntil { rig.sends.get() > 0 }, "the active scanner never sent a request")

        val settled = CountDownLatch(1)
        scanner.requestEnabled(false) { settled.countDown() }
        assertTrue(settled.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "the active scanner OFF request never settled")
        assertFalse(scanner.getStatus().scanning, "the active scanner must be stopped after OFF settled")
        return rig.sends.get()
    }

    /** A passive manual scan of one request; asserts it ran to completion. */
    private fun runPassiveManualScan(rig: ActiveScannerRig) {
        val finished = CountDownLatch(1)
        val queued =
            App.passiveAiScanner.manualScan(listOf(rig.requestResponse())) { completed, total ->
                if (completed >= total) finished.countDown()
            }
        assertEquals(1, queued, "the passive manual scan must queue its request")
        assertTrue(finished.await(ACTIVITY_SECONDS, TimeUnit.SECONDS), "the passive manual scan never finished")
    }

    /** Starts MCP the way a settings write would, on port 0; returns the port the kernel bound. */
    private fun startMcpOnPortZero(api: MontoyaApi): Int {
        val before = boundPorts.size
        val settings = AgentSettingsRepository(api).load()
        App.mcpSupervisor.applySettings(
            settings.mcpSettings.copy(
                enabled = true,
                host = LOOPBACK,
                port = 0,
                externalEnabled = false,
                stdioEnabled = false,
                tlsEnabled = false,
                token = "unload-leak-probe-token",
            ),
            settings.privacyMode,
            settings.determinismMode,
            settings.toPreprocessorSettings(),
        )
        assertTrue(pollUntil { boundPorts.size > before }, "the MCP server never reported a bound port")
        return boundPorts.last()
    }

    /** `GET /__mcp/health` over a plain socket (no client library, so no client threads of its own). */
    private fun healthAnswers(port: Int): Boolean =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(LOOPBACK, port), CONNECT_TIMEOUT_MS)
            socket.soTimeout = READ_TIMEOUT_MS
            socket.getOutputStream().write(request("/__mcp/health", "Connection: close").toByteArray(Charsets.US_ASCII))
            val reply = socket.getInputStream().readBytes().toString(Charsets.UTF_8)
            reply.startsWith("HTTP/1.1 200") && reply.endsWith("ok")
        }

    /**
     * Opens `GET /sse` and reads until the server sent its first event; the socket stays open across the
     * unload (closed in [restore]). Returns what was read.
     */
    private fun openSseSession(port: Int): String {
        val socket = Socket().also { sockets += it }
        socket.connect(InetSocketAddress(LOOPBACK, port), CONNECT_TIMEOUT_MS)
        socket.soTimeout = READ_TIMEOUT_MS
        socket.getOutputStream().write(request("/sse", "Accept: text/event-stream").toByteArray(Charsets.US_ASCII))
        val read = ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER_BYTES)
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(ACTIVITY_SECONDS)
        var n = 0
        while (n >= 0 && System.nanoTime() < end && !read.toString(Charsets.UTF_8).contains("event:")) {
            n = readOrEnd(socket, buffer)
            if (n > 0) read.write(buffer, 0, n)
        }
        val text = read.toString(Charsets.UTF_8)
        assertTrue(text.startsWith("HTTP/1.1 200"), "the SSE request must be accepted: ${text.lineSequence().firstOrNull()}")
        assertTrue(text.contains("text/event-stream"), "the SSE request must get an event stream")
        assertTrue(text.contains("event:"), "the SSE session must send its first event")
        return text
    }

    /** Bytes read into [buffer], or -1 at end of stream or when the read timed out. */
    private fun readOrEnd(
        socket: Socket,
        buffer: ByteArray,
    ): Int =
        try {
            socket.getInputStream().read(buffer)
        } catch (_: SocketTimeoutException) {
            -1
        }

    /** Local mode checks the Host header against loopback; a Host without a port matches any bound port. */
    private fun request(
        path: String,
        header: String,
    ): String = "GET $path HTTP/1.1\r\nHost: $LOOPBACK\r\nUser-Agent: unload-leak-probe\r\n$header\r\n\r\n"

    private fun liveThreads(): Set<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive }
            .toSet()

    /** New threads (absent from [before]) whose names match [patterns], polled for up to 5 s until none. */
    private fun pollForLeaks(
        before: Set<Thread>,
        patterns: List<Regex>,
    ): List<Thread> =
        pollUntilEmpty {
            (liveThreads() - before).filter { thread -> patterns.any { it.matches(thread.name) } }
        }

    private fun pollUntilEmpty(probe: () -> List<Thread>): List<Thread> {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(LEAK_POLL_SECONDS)
        while (System.nanoTime() < end) {
            if (probe().isEmpty()) return emptyList()
            Thread.sleep(POLL_MS)
        }
        return probe()
    }

    private fun pollUntil(condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(ACTIVITY_SECONDS)
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(POLL_MS)
        }
        return condition()
    }

    private fun describe(threads: List<Thread>): String = threads.joinToString { "${it.name} (daemon=${it.isDaemon}, ${it.state})" }

    private fun isListening(port: Int): Boolean =
        try {
            Socket().use { it.connect(InetSocketAddress(LOOPBACK, port), CONNECT_TIMEOUT_MS) }
            true
        } catch (_: ConnectException) {
            false
        }

    private companion object {
        const val LAST = Int.MAX_VALUE
        const val PREFIX = "burp-ai-agent-"
        const val COROUTINE_WORKER = "DefaultDispatcher-worker-"
        const val LOOPBACK = "127.0.0.1"
        const val CHAT_ANSWER = "unload-leak-probe answer"
        const val UNLOAD_SECONDS = 12L
        const val LEAK_POLL_SECONDS = 5L
        const val ACTIVITY_SECONDS = 10L
        const val POLL_MS = 50L
        const val CONNECT_TIMEOUT_MS = 500
        const val READ_TIMEOUT_MS = 5_000
        const val BUFFER_BYTES = 4096

        /** The thread names SC1 forbids after an unload (new threads only). */
        val LEAK_PATTERNS =
            listOf(
                Regex("$PREFIX.*"),
                Regex("""pool-\d+-thread-\d+"""),
                Regex("""Thread-\d+"""),
                Regex("eventLoopGroupProxy-.*"),
            )
    }
}
