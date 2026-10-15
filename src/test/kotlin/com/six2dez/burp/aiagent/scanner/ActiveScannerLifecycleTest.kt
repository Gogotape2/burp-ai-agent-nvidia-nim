package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import burp.api.montoya.core.ByteArray as MontoyaByteArray

/**
 * Phase 33 / EDT-01, D-01, D-04, D-05, D-11 — the active scanner's lifecycle.
 *
 * - Turning the scanner OFF from the EDT returns at once: the stop runs on the daemon
 *   `burp-ai-agent-scan-lifecycle` thread and the status reports `stopping` until it finishes (D-04).
 * - A second toggle made while a stop runs is serialized behind it, and the latest intent wins (D-04).
 * - A manual scan started on the EDT while a stop runs does not block the EDT.
 * - Enabling a running scanner is a no-op: the worker pool is not recreated (D-01).
 * - Every pool comes from the thread helper: named, daemon threads (D-11).
 * - `shutdown(deadline)` returns within the shared unload deadline with a request stuck on the wire (D-05).
 *
 * The lever that keeps a stop running is the constructor's `getSettings` lambda, scoped to scan worker
 * threads: `executeScan` calls it first, so a worker that waits there (ignoring interrupts) holds the stop
 * in its bounded wait for as long as the test wants. Every latch is released and every scanner shut down
 * in `finally` / `@AfterEach`.
 */
class ActiveScannerLifecycleTest {
    private val rig = ActiveScannerRig()

    @AfterEach
    fun tearDown() {
        rig.close()
    }

    @Test
    fun turningTheScannerOffFromTheEdtReturnsAtOnceAndTheStopRunsOnTheLifecycleThread() {
        val hold = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val scanner = rig.scanner(holdingWorkers(entered, hold))
        try {
            scanner.setEnabled(true)
            scanner.queueTarget(rig.target())
            assertTrue(entered.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a worker must pick the target up")
            warmUpEdt()

            val settledOn = AtomicReference<Thread?>()
            val settled = CountDownLatch(1)
            assertTimeoutPreemptively(Duration.ofSeconds(EDT_RETURN_SECONDS)) {
                SwingUtilities.invokeAndWait {
                    scanner.requestEnabled(false) {
                        settledOn.set(Thread.currentThread())
                        settled.countDown()
                    }
                }
            }

            val during = scanner.getStatus()
            assertTrue(during.stopping, "the status must say the scanner is stopping while the stop runs")
            assertFalse(during.enabled, "the intent is OFF at once")

            hold.countDown()
            assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the stop must settle once the worker is released")
            assertEquals(LIFECYCLE_THREAD, settledOn.get()?.name, "the stop runs on the lifecycle thread")
            assertTrue(settledOn.get()?.isDaemon == true, "the lifecycle thread is daemon")
            val after = scanner.getStatus()
            assertFalse(after.stopping, "stopping clears once the stop finished")
            assertFalse(after.scanning, "the scanner no longer scans")
        } finally {
            hold.countDown()
        }
    }

    @Test
    fun aSecondToggleWhileAStopRunsIsSerializedBehindItAndAManualScanOnTheEdtDoesNotBlock() {
        val hold = CountDownLatch(1)
        val entered = CountDownLatch(1)
        val scanner = rig.scanner(holdingWorkers(entered, hold))
        try {
            scanner.setEnabled(true)
            val firstPool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }
            scanner.queueTarget(rig.target())
            assertTrue(entered.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a worker must pick the target up")
            warmUpEdt()

            val events = CopyOnWriteArrayList<String>()
            val settled = CountDownLatch(2)
            scanner.requestEnabled(false) {
                events += "stop scanning=${scanner.getStatus().scanning} oldPoolTerminated=${firstPool.isTerminated}"
                settled.countDown()
            }
            // The stop is running on the lifecycle thread once it has cleared `scanning`; it now waits
            // for the held worker.
            assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
                while (scanner.getStatus().scanning) Thread.sleep(POLL_MS)
            }
            scanner.requestEnabled(true) {
                events += "start scanning=${scanner.getStatus().scanning} oldPoolTerminated=${firstPool.isTerminated}"
                settled.countDown()
            }
            assertTimeoutPreemptively(Duration.ofSeconds(EDT_RETURN_SECONDS)) {
                SwingUtilities.invokeAndWait { scanner.manualScan(listOf(rig.requestResponse()), listOf(VulnClass.SQLI)) }
            }
            assertTrue(events.isEmpty(), "nothing settles while the stop is held: $events")

            hold.countDown()
            assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS), "both requests must settle")
            assertEquals(
                listOf("stop scanning=false oldPoolTerminated=true", "start scanning=true oldPoolTerminated=true"),
                events.toList(),
                "callbacks arrive in request order and the start runs only after the stop finished",
            )
            val status = scanner.getStatus()
            assertTrue(status.enabled, "the latest request (ON) wins")
            assertTrue(status.scanning, "the latest request (ON) wins")
            assertFalse(status.stopping)
            assertNotSame(firstPool, scanner.workerPoolForTests(), "the start built a fresh pool after the stop")
        } finally {
            hold.countDown()
        }
    }

    @Test
    fun enablingARunningScannerAgainDoesNotRestartIt() {
        val scanner = rig.scanner()
        scanner.setEnabled(true)
        val pool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }

        scanner.setEnabled(true)

        assertSame(pool, scanner.workerPoolForTests(), "D-01: an already running scanner is not restarted")
        assertFalse(pool.isShutdown, "the running pool is untouched")
    }

    @Test
    fun theScannerPoolsAreNamedDaemonThreadsFromTheHelper() {
        val workerThreads = CopyOnWriteArrayList<Thread>()
        val scanned = CountDownLatch(1)
        val scanner =
            rig.scanner {
                if (onScanWorker()) {
                    workerThreads += Thread.currentThread()
                    scanned.countDown()
                }
                TestSettings.baselineSettings()
            }
        val before = Thread.getAllStackTraces().keys
        scanner.setEnabled(true)
        scanner.queueTarget(rig.target())
        assertTrue(scanned.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a worker must pick the target up")
        val settled = CountDownLatch(1)
        val lifecycleThread = AtomicReference<Thread?>()
        scanner.requestEnabled(true) {
            lifecycleThread.set(Thread.currentThread())
            settled.countDown()
        }
        assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS))

        val started = Thread.getAllStackTraces().keys - before
        val names = started.map { it.name }.toSet()
        assertTrue("burp-ai-agent-scan-scheduler" in names, "scheduler thread missing: $names")
        assertTrue("burp-ai-agent-oast-poller" in names, "OAST poller thread missing: $names")
        assertTrue(workerThreads.all { Regex("burp-ai-agent-scan-worker-\\d+").matches(it.name) }, "worker names: $workerThreads")
        assertEquals(LIFECYCLE_THREAD, lifecycleThread.get()?.name)
        val ours = started + workerThreads + listOfNotNull(lifecycleThread.get())
        assertTrue(ours.filter { it.name.startsWith("burp-ai-agent-") }.all { it.isDaemon }, "every scanner thread is daemon")
    }

    @Test
    fun shutdownWithARequestStuckOnTheWireReturnsWithinTheDeadlineAndStartsNothingAfterwards() {
        val onWire = CountDownLatch(1)
        val release = CountDownLatch(1)
        rig.onSend = {
            onWire.countDown()
            awaitIgnoringInterrupts(release)
        }
        val scanner = rig.scanner()
        try {
            scanner.setEnabled(true)
            val workers = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }
            scanner.queueTarget(rig.target())
            assertTrue(onWire.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a request must reach the wire")

            assertTimeoutPreemptively(Duration.ofSeconds(SHUTDOWN_RETURN_SECONDS)) {
                scanner.shutdown(ShutdownDeadline(SHUTDOWN_BUDGET_MS))
            }
            assertTrue(workers.isTerminated, "no scan worker survives the shutdown")
            assertNull(scanner.workerPoolForTests())

            scanner.setEnabled(true)
            assertFalse(scanner.getStatus().scanning, "setEnabled after shutdown starts nothing")
            assertNull(scanner.workerPoolForTests())
            val settled = CountDownLatch(1)
            scanner.requestEnabled(true) { settled.countDown() }
            assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a request after shutdown still settles")
            assertFalse(scanner.getStatus().scanning, "requestEnabled after shutdown starts nothing")
            assertFalse(scanner.getStatus().stopping)
        } finally {
            release.countDown()
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Settings hot-apply (D-01, D-03)
    // ---------------------------------------------------------------------------------------------

    @Test
    fun settingMaxConcurrentOnARunningScannerResizesTheLivePoolInBothDirections() {
        val scanner = rig.scanner()
        scanner.maxConcurrent = 3
        scanner.setEnabled(true)
        val pool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }

        scanner.maxConcurrent = 5
        assertSame(pool, scanner.workerPoolForTests(), "D-01: growing resizes the live pool, never recreates it")
        assertEquals(5, pool.corePoolSize, "core follows maxConcurrent when growing")
        assertEquals(5, pool.maximumPoolSize, "maximum follows maxConcurrent when growing")

        scanner.maxConcurrent = 2
        assertSame(pool, scanner.workerPoolForTests(), "D-01: shrinking resizes the live pool, never recreates it")
        assertEquals(2, pool.corePoolSize, "core follows maxConcurrent when shrinking")
        assertEquals(2, pool.maximumPoolSize, "maximum follows maxConcurrent when shrinking: the pool never exceeds it")
    }

    @Test
    fun maxConcurrentBelowOneIsClampedToOne() {
        val scanner = rig.scanner()
        scanner.setEnabled(true)
        val pool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }

        scanner.maxConcurrent = 0

        assertEquals(1, scanner.maxConcurrent, "0 is clamped to 1")
        assertEquals(1, pool.corePoolSize)
        assertEquals(1, pool.maximumPoolSize)
    }

    @Test
    fun maxConcurrentOnAStoppedScannerBuildsNoPoolAndTheNextStartUsesIt() {
        val scanner = rig.scanner()

        scanner.maxConcurrent = 4
        assertNull(scanner.workerPoolForTests(), "a stopped scanner has no pool to resize and builds none")

        scanner.setEnabled(true)
        val pool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }
        assertEquals(4, pool.corePoolSize)
        assertEquals(4, pool.maximumPoolSize)
    }

    @Test
    fun aSettingsChangeKeepsTheSharedBaselinesAndThePoolAndOnlyDisableDropsThem() {
        val scanner = rig.scanner()
        scanner.setEnabled(true)
        scanner.queueTarget(rig.target())
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (scanner.getStatus().scansCompleted < 1) Thread.sleep(POLL_MS)
        }
        val baselines = scanner.baselineCacheSizeForTests()
        assertTrue(baselines > 0, "anti-vacuity: the scanned target must have cached its baseline")
        val pool = scanner.workerPoolForTests()

        scanner.maxPayloadsPerPoint = 7
        scanner.timeoutSeconds = 12
        scanner.requestDelayMs = 50
        scanner.maxRiskLevel = PayloadRisk.MODERATE
        scanner.scopeOnly = true
        scanner.scanMode = ScanMode.BUG_BOUNTY
        scanner.useCollaborator = true
        scanner.maxConcurrent = 4
        scanner.setEnabled(true)

        assertEquals(baselines, scanner.baselineCacheSizeForTests(), "D-03: a settings change keeps the shared baselines")
        assertSame(pool, scanner.workerPoolForTests(), "D-01: a settings change does not restart the scanner")
        assertTrue(scanner.getStatus().scanning)

        scanner.setEnabled(false)
        assertEquals(0, scanner.baselineCacheSizeForTests(), "D-03: disabling the scanner drops the shared baselines")
        assertEquals(0, scanner.pendingOastCountForTests(), "D-03: disabling the scanner drops pending Collaborator confirmations")
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** A settings lever that parks every scan worker at the top of `executeScan` until [hold] opens. */
    private fun holdingWorkers(
        entered: CountDownLatch,
        hold: CountDownLatch,
    ): () -> AgentSettings =
        {
            if (onScanWorker()) {
                entered.countDown()
                awaitIgnoringInterrupts(hold)
            }
            TestSettings.baselineSettings()
        }

    private fun warmUpEdt() {
        SwingUtilities.invokeAndWait {}
    }

    private companion object {
        const val LIFECYCLE_THREAD = "burp-ai-agent-scan-lifecycle"
        const val AWAIT_SECONDS = 15L
        const val EDT_RETURN_SECONDS = 1L
        const val SHUTDOWN_RETURN_SECONDS = 5L
        const val SHUTDOWN_BUDGET_MS = 2_000L
        const val POLL_MS = 10L
    }
}

/** True on the scanner's scan worker threads, the only threads that run `executeScan`. */
internal fun onScanWorker(): Boolean = Thread.currentThread().name.startsWith("burp-ai-agent-scan-worker-")

/**
 * Waits for [latch] the way an uninterruptible Montoya call would: an interrupt does not end the wait.
 * The interrupt flag is restored afterwards so the caller still sees it.
 */
internal fun awaitIgnoringInterrupts(latch: CountDownLatch) {
    var interrupted = false
    while (true) {
        try {
            latch.await()
            break
        } catch (_: InterruptedException) {
            interrupted = true
        }
    }
    if (interrupted) Thread.currentThread().interrupt()
}

/**
 * A live [ActiveAiScanner] over a mocked Montoya API whose `http().sendRequest` answers every request
 * with `200 ok 42` and counts it. Statics (`HttpRequestResponse.httpRequestResponse`) are served by a
 * mock object factory installed for the rig's lifetime. The target request is a fake POST with one body
 * parameter, so a payload is injected through `withBody` and no static request builder is needed.
 *
 * Shared by [ActiveScannerLifecycleTest] and [ActiveScannerStopInterruptTest]; [close] shuts every
 * scanner down and restores the factory.
 */
internal class ActiveScannerRig : AutoCloseable {
    private val savedFactory: MontoyaObjectFactory? = ObjectFactoryLocator.FACTORY
    private val scanners = CopyOnWriteArrayList<ActiveAiScanner>()

    /** Requests that reached `sendRequest`, counted on entry (a request on the wire is counted). */
    val sends = AtomicInteger(0)

    /** Runs on the request thread after the count, before the answer; may block. */
    @Volatile
    var onSend: (Int) -> Unit = {}

    private val http: Http =
        Mockito.mock(
            Http::class.java,
            Answer<Any?> { invocation ->
                if (invocation.method.name == "sendRequest") {
                    val request = invocation.getArgument<HttpRequest>(0)
                    onSend(sends.incrementAndGet())
                    pairOf(request, okResponse())
                } else {
                    Answers.RETURNS_DEFAULTS.answer(invocation)
                }
            },
        )

    val api: MontoyaApi =
        mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also { whenever(it.http()).thenReturn(http) }

    init {
        val options = mock<RequestOptions>(defaultAnswer = Answers.RETURNS_SELF)
        val factory = mock<MontoyaObjectFactory>(defaultAnswer = Answers.RETURNS_MOCKS)
        whenever(factory.requestOptions()).thenReturn(options)
        whenever(factory.httpRequestResponse(any<HttpRequest>(), any<HttpResponse>())).thenAnswer { invocation ->
            pairOf(invocation.getArgument(0), invocation.getArgument(1))
        }
        ObjectFactoryLocator.FACTORY = factory
    }

    fun scanner(getSettings: () -> AgentSettings = { TestSettings.baselineSettings() }): ActiveAiScanner {
        val created = ActiveAiScanner(api, mock<AgentSupervisor>(), mock<AuditLogger>(), getSettings)
        created.scopeOnly = false
        created.scanMode = ScanMode.FULL
        created.requestDelayMs = 0
        created.maxPayloadsPerPoint = 1
        scanners += created
        return created
    }

    /** One body-parameter target on [requestResponse] for [vulnClass]. */
    fun target(vulnClass: VulnClass = VulnClass.SQLI): ActiveScanTarget =
        ActiveScanTarget(
            originalRequest = requestResponse(),
            injectionPoint = InjectionPoint(InjectionType.BODY_PARAM, PARAM, VALUE),
            vulnHint = VulnHint(vulnClass, 50, "test"),
            priority = 50,
        )

    /** The original request (`POST /form` with body `a=1`) paired with no response. */
    fun requestResponse(): HttpRequestResponse = pairOf(fakeRequest("$PARAM=$VALUE"), null)

    /** Every line written to `api.logging().logToError`. */
    fun errorLines(): List<String> =
        Mockito
            .mockingDetails(api.logging())
            .invocations
            .filter { it.method.name == "logToError" }
            .map { it.arguments.first().toString() }

    override fun close() {
        scanners.forEach { runCatching { it.shutdown() } }
        scanners.clear()
        ObjectFactoryLocator.FACTORY = savedFactory
    }

    private fun fakeRequest(body: String): HttpRequest {
        val service =
            answering(HttpService::class.java) { name, _ ->
                when (name) {
                    "host" -> "target.example"
                    "port" -> 443
                    "secure" -> true
                    else -> DEFAULT
                }
            }
        val raw = "POST /form HTTP/1.1\r\nHost: target.example\r\n\r\n$body".toByteArray(Charsets.UTF_8)
        val bytes = answering(MontoyaByteArray::class.java) { name, _ -> if (name == "getBytes") raw.copyOf() else DEFAULT }
        val parameter =
            answering(ParsedHttpParameter::class.java) { name, _ ->
                when (name) {
                    "type" -> HttpParameterType.BODY
                    "name" -> PARAM
                    "value" -> VALUE
                    else -> DEFAULT
                }
            }
        return answering(HttpRequest::class.java) { name, args ->
            when (name) {
                "httpService" -> service
                "toByteArray" -> bytes
                "parameters" -> listOf(parameter)
                else -> requestAnswer(body, name, args)
            }
        }
    }

    private fun requestAnswer(
        body: String,
        name: String,
        args: Array<Any?>,
    ): Any? =
        when (name) {
            "method" -> "POST"
            "url" -> "https://target.example/form"
            "path" -> "/form"
            "httpVersion" -> "HTTP/1.1"
            "headers" -> emptyList<Any>()
            "headerValue" -> if (args.first() == "Content-Type") FORM_TYPE else null
            "bodyToString" -> body
            "withBody" -> fakeRequest(args.first().toString())
            "withPath", "withMethod", "withAddedHeader", "withRemovedHeader" -> fakeRequest(body)
            else -> DEFAULT
        }

    private fun okResponse(): HttpResponse {
        val body = answering(MontoyaByteArray::class.java) { name, _ -> if (name == "length") RESPONSE_BODY.length else DEFAULT }
        return answering(HttpResponse::class.java) { name, _ ->
            when (name) {
                "statusCode" -> 200.toShort()
                "bodyToString" -> RESPONSE_BODY
                "body" -> body
                "headers" -> emptyList<Any>()
                else -> DEFAULT
            }
        }
    }

    private fun pairOf(
        sent: HttpRequest?,
        answer: HttpResponse?,
    ): HttpRequestResponse =
        answering(HttpRequestResponse::class.java) { name, _ ->
            when (name) {
                "request" -> sent
                "response" -> answer
                else -> DEFAULT
            }
        }

    /** A mock answered by [answer] per method name; [DEFAULT] falls back to Mockito's defaults. */
    private fun <T> answering(
        type: Class<T>,
        answer: (String, Array<Any?>) -> Any?,
    ): T =
        Mockito.mock(
            type,
            Answer<Any?> { invocation ->
                val result = answer(invocation.method.name, invocation.arguments)
                if (result === DEFAULT) Answers.RETURNS_DEFAULTS.answer(invocation) else result
            },
        )

    private companion object {
        val DEFAULT = Any()
        const val PARAM = "a"
        const val VALUE = "1"
        const val RESPONSE_BODY = "ok 42"
        const val FORM_TYPE = "application/x-www-form-urlencoded"
    }
}
