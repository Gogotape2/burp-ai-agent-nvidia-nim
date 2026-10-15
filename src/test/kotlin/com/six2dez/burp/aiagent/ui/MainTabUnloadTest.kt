package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.agents.AgentProfileLoader
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpServerState
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.junit.jupiter.api.io.TempDir
import org.mockito.Answers
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

/**
 * Phase 33 / LIFE-01, D-06 — MainTab builds headless, quiesces without waiting, and its dispose removes
 * the change listener it added to Burp's tab pane and stops its health thread.
 *
 * Runs in the normal `test` task: it never touches `App`. The collaborators are real where MainTab's
 * construction reads them (settings store, backend registry, chat supervisor over the strict store
 * policy) and mocks elsewhere, like TestConnectionRefusalTest.
 */
class MainTabUnloadTest {
    @TempDir
    lateinit var profileHome: Path

    private val tabs = CopyOnWriteArrayList<MainTab>()
    private val supervisors = CopyOnWriteArrayList<AgentSupervisor>()

    // Every Error line any MainTab built by this test writes (newApi captures them).
    private val errors = CopyOnWriteArrayList<String>()

    // A latch a test uses to hold the EDT busy; released in disposeEverything as well, so a failing case
    // cannot wedge the EDT for the tests after it.
    private val edtRelease = CountDownLatch(1)

    @BeforeEach
    fun isolateProfiles() {
        AgentProfileLoader.setBaseDirForTests(profileHome)
    }

    @AfterEach
    fun disposeEverything() {
        edtRelease.countDown()
        tabs.forEach { tab ->
            runCatching {
                tab.quiesce()
                tab.dispose(ShutdownDeadline(DISPOSE_BUDGET_MS))
            }
        }
        tabs.clear()
        supervisors.forEach { runCatching { it.shutdown() } }
        supervisors.clear()
        AgentProfileLoader.setBaseDirForTests(null)
    }

    @Test
    fun mainTabIsConstructedHeadlessWithoutAnException() {
        val tab = newMainTab()

        assertNotNull(tab.root, "MainTab built headless exposes its root")
    }

    @Test
    fun disposeFromAWorkerThreadRemovesTheTabPaneListenerAndStopsTheHealthThread() {
        val healthPoolsBefore = healthPools()
        val tab = newMainTab()
        val pane = placeInTabbedPane(tab)
        val listenersBefore = onEdt { pane.changeListeners.size }

        val attached = onEdt { tab.attachTabPaneForTests() }
        assertSame(pane, attached, "the tab finds the pane it sits in")
        assertEquals(listenersBefore + 1, onEdt { pane.changeListeners.size }, "attaching adds exactly one listener")

        // Make the health pool start its thread, so the stop is observable.
        val healthPool = (healthPools() - healthPoolsBefore).single()
        healthPool.submit {}.get(AWAIT_SECONDS, TimeUnit.SECONDS)
        assertTrue(liveHealthThreads().isNotEmpty(), "the health pool has a live burp-ai-agent-health thread")

        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            tab.quiesce()
            tab.dispose(ShutdownDeadline(DISPOSE_BUDGET_MS))
        }
        tabs.remove(tab)

        assertEquals(listenersBefore, onEdt { pane.changeListeners.size }, "dispose removes the listener it added")
        assertTrue(healthPool.isShutdown, "dispose stops the health pool")
        assertTrue(healthPool.awaitTermination(AWAIT_SECONDS, TimeUnit.SECONDS), "the health pool terminates")
        assertTrue(pollUntil { liveHealthThreads().isEmpty() }, "no burp-ai-agent-health thread is left: ${liveHealthThreads()}")
    }

    @Test
    fun disposeOnTheEdtItselfAlsoRemovesTheListener() {
        val tab = newMainTab()
        val pane = placeInTabbedPane(tab)
        val listenersBefore = onEdt { pane.changeListeners.size }
        onEdt { tab.attachTabPaneForTests() }
        assertEquals(listenersBefore + 1, onEdt { pane.changeListeners.size })

        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS), "dispose on the EDT must not deadlock") {
            SwingUtilities.invokeAndWait {
                tab.quiesce()
                tab.dispose(ShutdownDeadline(DISPOSE_BUDGET_MS))
            }
        }
        tabs.remove(tab)

        assertEquals(listenersBefore, onEdt { pane.changeListeners.size }, "dispose on the EDT removes the listener")
    }

    @Test
    fun quiesceReturnsWithoutWaiting() {
        val tab = newMainTab()

        assertTimeoutPreemptively(Duration.ofSeconds(1), "quiesce takes no lock and waits for nothing") {
            tab.quiesce()
        }
    }

    /**
     * WR-03 / D-05 / D-09 — with the EDT busy, dispose waits on it only within the shared deadline, then
     * names each part whose teardown did not run in time, once, and returns. The posted teardown still
     * runs on the EDT once it is free (D-06), so the listener is removed in the end.
     */
    @Test
    fun disposeWithTheEdtBusyReturnsWithinItsDeadlineAndNamesWhatDidNotStop() {
        val tab = newMainTab()
        val pane = placeInTabbedPane(tab)
        val listenersBefore = onEdt { pane.changeListeners.size }
        onEdt { tab.attachTabPaneForTests() }
        assertEquals(listenersBefore + 1, onEdt { pane.changeListeners.size }, "attaching adds exactly one listener")

        try {
            holdEdtBusy()
            assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS), "dispose must not wait on a busy EDT past its deadline") {
                tab.quiesce()
                tab.dispose(ShutdownDeadline(BUSY_EDT_BUDGET_MS))
            }
            tabs.remove(tab)
        } finally {
            edtRelease.countDown()
        }
        onEdt { }

        assertEquals(
            1,
            errors.count { it == ShutdownDeadline.deadlineMissed("MainTab") },
            "exactly one MainTab deadline line: $errors",
        )
        assertEquals(
            1,
            errors.count { it == ShutdownDeadline.deadlineMissed("Chat panel") },
            "exactly one Chat panel deadline line: $errors",
        )
        assertEquals(listenersBefore, onEdt { pane.changeListeners.size }, "the late teardown still removes the listener")
    }

    @Test
    fun edtTeardownOnTheEdtRunsTheWorkInline() {
        val lines = CopyOnWriteArrayList<String>()
        val (returned, ranInline) =
            onEdt {
                var ran = false
                val ok = EdtTeardown.runWithin("Inline", ShutdownDeadline(DISPOSE_BUDGET_MS), { lines += it }) { ran = true }
                ok to ran
            }

        assertTrue(returned, "runWithin on the EDT reports the work done")
        assertTrue(ranInline, "the work ran before runWithin returned, so it ran inline and did not wait on itself")
        assertTrue(lines.isEmpty(), "a clean teardown writes nothing: $lines")
    }

    @Test
    fun edtTeardownFromAWorkerRunsTheWorkOnTheEdtAndWritesNothing() {
        val lines = CopyOnWriteArrayList<String>()
        val ranOnEdt = AtomicReference<Boolean>()

        val returned =
            EdtTeardown.runWithin("Worker", ShutdownDeadline(DISPOSE_BUDGET_MS), { lines += it }) {
                ranOnEdt.set(SwingUtilities.isEventDispatchThread())
            }

        assertTrue(returned, "the EDT was free, so the work finished within the deadline")
        assertEquals(true, ranOnEdt.get(), "the work ran on the EDT")
        assertTrue(lines.isEmpty(), "a clean teardown writes nothing: $lines")
    }

    @Test
    fun edtTeardownReportsAThrowingWorkOnceAndTheWaiterStillReturns() {
        val lines = CopyOnWriteArrayList<String>()

        assertTimeoutPreemptively(Duration.ofSeconds(1), "a throwing work must still release the waiter") {
            EdtTeardown.runWithin("Boom part", ShutdownDeadline(DISPOSE_BUDGET_MS), { lines += it }) {
                throw IllegalStateException("boom")
            }
        }

        assertEquals(listOf("Boom part shutdown failed: boom"), lines.toList())
    }

    @Test
    fun edtTeardownPostFromAWorkerNeverWaits() {
        val lines = CopyOnWriteArrayList<String>()
        val runs = AtomicInteger()
        try {
            holdEdtBusy()
            assertTimeoutPreemptively(Duration.ofSeconds(1), "post must not wait on a busy EDT") {
                EdtTeardown.post("Posted", { lines += it }) { runs.incrementAndGet() }
            }
            assertEquals(0, runs.get(), "the EDT is still busy, so the posted work has not run yet")
        } finally {
            edtRelease.countDown()
        }
        onEdt { }

        assertEquals(1, runs.get(), "the posted work runs once the EDT is drained")
        assertTrue(lines.isEmpty(), "a clean teardown writes nothing: $lines")
    }

    private fun newMainTab(): MainTab {
        val api = newApi()
        val registry = BackendRegistry(api)
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), StoreAiAccessPolicy()).also { supervisors += it }
        // A real state: deep stubs cannot mock the sealed McpServerState the status timer reads.
        val mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        doReturn(McpServerState.Stopped).whenever(mcpSupervisor).status()
        val tab =
            MainTab(
                api,
                AgentSettingsRepository(api),
                registry,
                supervisor,
                mock<AuditLogger>(),
                mcpSupervisor,
                mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                mock<ActiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                AiRequestLogger(),
                buildIdentity = "Custom AI Agent test (test build)",
            )
        tabs += tab
        return tab
    }

    private fun newApi(): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = InMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        // Capture Error lines before construction, so every line the tab writes reaches [errors]. The
        // deep-stubbed logging() is resolved first, for the same UnfinishedStubbingException reason.
        val logging = api.logging()
        doAnswer { invocation ->
            errors += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyOrNull<String>())
        return api
    }

    /** Holds the EDT on [edtRelease]; returns once the EDT is inside the holding runnable. */
    private fun holdEdtBusy() {
        val entered = CountDownLatch(1)
        SwingUtilities.invokeLater {
            entered.countDown()
            edtRelease.await(EDT_HOLD_SECONDS, TimeUnit.SECONDS)
        }
        assertTrue(entered.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the EDT picked up the holding runnable")
    }

    private fun placeInTabbedPane(tab: MainTab): JTabbedPane =
        onEdt {
            JTabbedPane().apply { addTab("Custom AI Agent", tab.root) }
        }

    private fun healthPools(): Set<ExecutorService> =
        ExtensionThreads
            .trackedSnapshot()
            .filterValues { it == "health" }
            .keys

    private fun liveHealthThreads(): List<Thread> =
        Thread
            .getAllStackTraces()
            .keys
            .filter { it.isAlive && it.name == "burp-ai-agent-health" }

    private fun pollUntil(condition: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(AWAIT_SECONDS)
        while (System.nanoTime() < end) {
            if (condition()) return true
            Thread.sleep(POLL_MS)
        }
        return condition()
    }

    private fun <T> onEdt(block: () -> T): T {
        val result = AtomicReference<T>()
        SwingUtilities.invokeAndWait { result.set(block()) }
        return result.get()
    }

    private companion object {
        const val DISPOSE_BUDGET_MS = 5_000L
        const val BUSY_EDT_BUDGET_MS = 300L
        const val EDT_HOLD_SECONDS = 30L
        const val AWAIT_SECONDS = 5L
        const val POLL_MS = 25L
    }
}
