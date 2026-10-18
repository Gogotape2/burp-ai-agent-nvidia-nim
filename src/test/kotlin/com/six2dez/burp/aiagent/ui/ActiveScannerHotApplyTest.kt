package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.mcp.McpSupervisor
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScannerRig
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.scanner.awaitIgnoringInterrupts
import com.six2dez.burp.aiagent.scanner.onScanWorker
import com.six2dez.burp.aiagent.spi.StoreAiAccessPolicy
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * Phase 33 / EDT-01, D-01, D-03, D-04 (SC5) — the Settings tab's active scanner controls on a real
 * [SettingsPanel] over a real [ActiveAiScanner].
 *
 * - Every control except the on/off toggle hot-applies: the worker pool instance survives, `maxConcurrent`
 *   resizes it, and the shared baselines are kept (D-01, D-03).
 * - Only the toggle (and the header toggle through [setActiveAiEnabled]) starts or stops the scanner,
 *   through `requestEnabled`, so turning it OFF on the EDT returns at once and the status label reads
 *   "Active: Stopping…" until the stop finishes (D-04).
 * - A second click during a stop is serialized behind it and the latest click wins (D-04).
 *
 * The lever that holds a stop open is the scanner's `getSettings` lambda on scan worker threads (the
 * first call in `executeScan`), the same one ActiveScannerLifecycleTest uses: a worker parked there,
 * ignoring interrupts, keeps the stop in its bounded wait until the test releases it.
 */
class ActiveScannerHotApplyTest {
    private val aiEnabled = AtomicBoolean(true)
    private val rig = ActiveScannerRig()
    private val panels = CopyOnWriteArrayList<SettingsPanel>()
    private val holds = CopyOnWriteArrayList<CountDownLatch>()

    @AfterEach
    fun tearDown() {
        holds.forEach { it.countDown() }
        panels.forEach { runCatching { it.shutdown() } }
        panels.clear()
        rig.close()
    }

    @Test
    fun scannerControlsHotApplyWithoutRestartingTheScannerOrDroppingBaselines() {
        val scanner = rig.scanner()
        val panel = newPanel(scanner)
        scanner.setEnabled(true)
        onEdt { panel.activeAiEnabled.isSelected = true }
        scanner.queueTarget(rig.target())
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (scanner.getStatus().scansCompleted < 1) Thread.sleep(POLL_MS)
        }
        val baselines = scanner.baselineCacheSizeForTests()
        assertTrue(baselines > 0, "anti-vacuity: the scanned target must have cached its baseline")
        val pool = requireNotNull(scanner.workerPoolForTests()) { "a running scanner has a worker pool" }

        onEdt { panel.activeAiMaxConcurrentSpinner.value = 5 }

        assertSame(pool, scanner.workerPoolForTests(), "D-01: maxConcurrent resizes the live pool, never recreates it")
        assertEquals(5, pool.corePoolSize, "core follows the spinner")
        assertEquals(5, pool.maximumPoolSize, "maximum follows the spinner")

        onEdt {
            panel.activeAiDelaySpinner.value = 200
            panel.activeAiMaxPayloadsSpinner.value = 6
            panel.activeAiTimeoutSpinner.value = 25
            panel.activeAiRiskLevelCombo.selectedItem = "MODERATE"
            panel.activeAiScanModeCombo.selectedItem = "PENTEST"
            panel.activeAiScopeOnly.doClick(0)
            panel.activeAiUseCollaborator.doClick(0)
            panel.activeAiAdaptivePayloads.doClick(0)
        }

        assertEquals(200L, scanner.requestDelayMs, "anti-vacuity: the delay spinner reached the scanner")
        assertEquals("PENTEST", scanner.scanMode.name, "anti-vacuity: the scan mode combo reached the scanner")
        assertSame(pool, scanner.workerPoolForTests(), "D-01: a control change never restarts the scanner")
        assertFalse(pool.isShutdown, "the running pool is untouched")
        assertEquals(baselines, scanner.baselineCacheSizeForTests(), "D-03: a control change keeps the shared baselines")
        assertTrue(scanner.isEnabled(), "the scanner stays on")
        assertTrue(scanner.getStatus().scanning, "the scanner keeps scanning")
    }

    @Test
    fun turningTheToggleOffOnTheEdtReturnsAtOnceAndTheLabelSaysStoppingUntilTheStopSettles() {
        val (scanner, panel, hold) = runningScannerWithAHeldWorker()

        val elapsedMs = clickOnEdt(panel)

        assertTrue(elapsedMs < EDT_RETURN_MS, "the click must return at once on the EDT, took $elapsedMs ms")
        val during =
            onEdtRead {
                panel.refreshActiveAiStatus()
                panel.activeAiStatusLabel.text
            }
        assertTrue(during.startsWith("Active: Stopping…"), "while the stop runs the label says so: $during")
        assertTrue(scanner.getStatus().stopping, "anti-vacuity: the stop is still running")

        hold.countDown()
        awaitLabel(panel, "Active: OFF")
        val after = scanner.getStatus()
        assertFalse(after.enabled)
        assertFalse(after.scanning, "the scanner stopped")
        assertFalse(after.stopping)
    }

    @Test
    fun aSecondClickDuringTheStopIsSerializedBehindItAndTheLatestClickWins() {
        val (scanner, panel, hold) = runningScannerWithAHeldWorker()

        val offMs = clickOnEdt(panel)
        val onMs = clickOnEdt(panel)

        assertTrue(offMs < EDT_RETURN_MS, "the OFF click must return at once, took $offMs ms")
        assertTrue(onMs < EDT_RETURN_MS, "the ON click during the stop must return at once, took $onMs ms")
        assertTrue(onEdtRead { panel.activeAiEnabled.isSelected }, "anti-vacuity: the second click turned the toggle back on")

        hold.countDown()
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (true) {
                val status = scanner.getStatus()
                if (status.enabled && status.scanning && !status.stopping) break
                Thread.sleep(POLL_MS)
            }
        }
        awaitLabel(panel, "Active: ON")
    }

    @Test
    fun theHeaderToggleTurnsTheScannerOffWithoutBlockingTheEdt() {
        val (scanner, panel, hold) = runningScannerWithAHeldWorker()

        val elapsedMs = AtomicLong(-1)
        assertTimeoutPreemptively(Duration.ofSeconds(EDT_TIMEOUT_SECONDS)) {
            SwingUtilities.invokeAndWait {
                val start = System.nanoTime()
                panel.setActiveAiEnabled(false)
                elapsedMs.set(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start))
            }
        }

        assertTrue(elapsedMs.get() < EDT_RETURN_MS, "the header path must return at once, took ${elapsedMs.get()} ms")
        hold.countDown()
        awaitLabel(panel, "Active: OFF")
        assertFalse(scanner.getStatus().enabled)
        assertFalse(scanner.getStatus().scanning)
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    private data class HeldScanner(
        val scanner: ActiveAiScanner,
        val panel: SettingsPanel,
        val hold: CountDownLatch,
    )

    /** A running scanner whose one worker is parked (ignoring interrupts) until `hold` opens; toggle ON. */
    private fun runningScannerWithAHeldWorker(): HeldScanner {
        val hold = CountDownLatch(1).also { holds += it }
        val entered = CountDownLatch(1)
        val scanner = rig.scanner(holdingWorkers(entered, hold))
        val panel = newPanel(scanner)
        scanner.setEnabled(true)
        onEdt { panel.activeAiEnabled.isSelected = true }
        scanner.queueTarget(rig.target())
        assertTrue(entered.await(AWAIT_SECONDS, TimeUnit.SECONDS), "a worker must pick the target up")
        onEdt {}
        return HeldScanner(scanner, panel, hold)
    }

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

    /** A user click on the Settings toggle, on the EDT; returns how long the EDT was busy with it. */
    private fun clickOnEdt(panel: SettingsPanel): Long {
        val elapsedMs = AtomicLong(-1)
        assertTimeoutPreemptively(Duration.ofSeconds(EDT_TIMEOUT_SECONDS)) {
            SwingUtilities.invokeAndWait {
                val start = System.nanoTime()
                panel.activeAiEnabled.doClick(0)
                elapsedMs.set(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start))
            }
        }
        return elapsedMs.get()
    }

    /** Waits until the status label starts with [prefix]; reads it on the EDT without refreshing it. */
    private fun awaitLabel(
        panel: SettingsPanel,
        prefix: String,
    ) {
        val last = AtomicReference("")
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(AWAIT_SECONDS)
        while (System.nanoTime() < deadline) {
            last.set(onEdtRead { panel.activeAiStatusLabel.text.orEmpty() })
            if (last.get().startsWith(prefix)) return
            Thread.sleep(POLL_MS)
        }
        throw AssertionError("the status label never started with '$prefix'; last: '${last.get()}'")
    }

    private fun onEdt(block: () -> Unit) {
        SwingUtilities.invokeAndWait { block() }
    }

    private fun <T> onEdtRead(block: () -> T): T {
        val result = AtomicReference<T>()
        SwingUtilities.invokeAndWait { result.set(block()) }
        return result.get()
    }

    private fun newPanel(scanner: ActiveAiScanner): SettingsPanel {
        val api = newApi()
        val registry = BackendRegistry(api)
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), StoreAiAccessPolicy())
        val panel =
            SettingsPanel(
                api = api,
                settingsRepo = AgentSettingsRepository(api),
                backends = registry,
                supervisor = supervisor,
                audit = mock<AuditLogger>(),
                mcpSupervisor = mock<McpSupervisor>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                passiveAiScanner = mock<PassiveAiScanner>(defaultAnswer = Answers.RETURNS_DEEP_STUBS),
                activeAiScanner = scanner,
                buildIdentity = "Custom AI Agent test (test build)",
            )
        panels.add(panel)
        return panel
    }

    private fun newApi(): MontoyaApi {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = InMemoryPreferences()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        whenever(api.ai().isEnabled()).thenAnswer { aiEnabled.get() }
        return api
    }

    private companion object {
        const val AWAIT_SECONDS = 15L
        const val EDT_TIMEOUT_SECONDS = 5L
        const val EDT_RETURN_MS = 1_000L
        const val POLL_MS = 10L
    }
}
