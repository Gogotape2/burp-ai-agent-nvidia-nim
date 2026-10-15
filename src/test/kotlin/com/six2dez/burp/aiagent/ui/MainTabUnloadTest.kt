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
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
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

    @BeforeEach
    fun isolateProfiles() {
        AgentProfileLoader.setBaseDirForTests(profileHome)
    }

    @AfterEach
    fun disposeEverything() {
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
        return api
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
        const val AWAIT_SECONDS = 5L
        const val POLL_MS = 25L
    }
}
