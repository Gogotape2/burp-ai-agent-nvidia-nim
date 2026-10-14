package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.scanner.SuggestedQueueOutcome
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import javax.swing.JOptionPane

/**
 * Phase 32 / D-04, D-05, D-08 — queuing suggested targets by hand runs, in order, the AI access policy
 * check, the enable-scanner prompt, the "Confirm AI Active Scan" confirmation, the real queue call,
 * the removal of the queued entries from the list and a result dialog. Nothing reaches the active
 * queue without a Yes. Driven through a real [SuggestedTargetList], a real (disabled) [ActiveAiScanner]
 * and a recording fake of the prompt seam, so no Swing dialog is ever shown.
 */
class SuggestedQueueDialogTest {
    private val logging = mock<Logging>()
    private val api =
        mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also {
            whenever(it.logging()).thenReturn(logging)
        }
    private val supervisor = mock<AgentSupervisor>()
    private val scanners = mutableListOf<ActiveAiScanner>()

    @AfterEach
    fun tearDown() {
        scanners.forEach { it.shutdown() }
        scanners.clear()
    }

    // --- Task 1: the confirmed flow ----------------------------------------------------------------

    @Test
    fun confirmedQueueMovesEveryEntryFromTheListIntoTheActiveQueue() {
        val scanner = newScanner()
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val ids = list.snapshot().map { it.target.id }
        val prompts = FakePrompts(enable = true, confirm = true)

        val outcome = SuggestedQueueAction(list, scanner, prompts).queue(list.snapshot())

        assertTrue(outcome is SuggestedQueueOutcome.Queued, "expected Queued, got $outcome")
        outcome as SuggestedQueueOutcome.Queued
        assertEquals(ids, outcome.queued.map { it.id })
        assertEquals(0, outcome.skipped)
        assertEquals(0, list.count(), "the queued entries leave the list")
        assertEquals(ids.toSet(), scanner.getQueueItems(10).map { it.id }.toSet())
        assertEquals(
            listOf(
                Call.Ensure,
                Call.Confirm(ManualScanDialogs.confirmActiveScanMessage(3, 2, 0)),
                Call.Show(ManualScanDialogs.suggested(outcome, scanner.maxQueueSize)),
            ),
            prompts.calls,
        )
    }

    @Test
    fun aSecondPressAfterAConfirmedQueueQueuesNothingAgain() {
        val scanner = newScanner()
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val ids = list.snapshot().map { it.target.id }
        SuggestedQueueAction(list, scanner, FakePrompts(enable = true, confirm = true)).queue(list.snapshot())
        val prompts = FakePrompts(enable = true, confirm = true)

        val again = SuggestedQueueAction(list, scanner, prompts).queue(list.snapshot())

        assertNull(again)
        assertEquals(listOf(Call.Show(ManualScanDialogs.NO_SUGGESTED_SELECTION)), prompts.calls)
        assertEquals(ids.sorted(), scanner.getQueueItems(10).map { it.id }.sorted(), "still exactly the three targets")
    }

    // --- Task 1: texts -----------------------------------------------------------------------------

    @Test
    fun confirmationTextCarriesTargetHostAndQueueCounts() {
        assertEquals(
            "This will send active test payloads to 3 target(s) on 2 host(s).\nCurrent queue: 0\n\nDo you want to continue?",
            ManualScanDialogs.confirmActiveScanMessage(3, 2, 0),
        )
        assertEquals("Confirm AI Active Scan", ManualScanDialogs.CONFIRM_ACTIVE_SCAN_TITLE)
        assertEquals(
            ScanDialog("Select one or more suggested targets to queue.", "No selection", JOptionPane.INFORMATION_MESSAGE),
            ManualScanDialogs.NO_SUGGESTED_SELECTION,
        )
    }

    @Test
    fun resultDialogsMatchTheContract() {
        val three = listOf(URL_A1, URL_A2, URL_B).map { target(it) }

        assertEquals(
            ScanDialog(
                "Queued 3 suggested target(s) for AI active testing.\n\n" +
                    "This will send test payloads to the server.\n" +
                    "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                "AI Active Scan Started",
                JOptionPane.INFORMATION_MESSAGE,
            ),
            ManualScanDialogs.suggested(SuggestedQueueOutcome.Queued(three, 0), 2000),
        )
        assertEquals(
            ScanDialog(
                "Queued 1 suggested target(s) for AI active testing.\n" +
                    "2 suggested target(s) were not queued (out of scope, not tested in the current scan mode, " +
                    "or the queue is full).\n\n" +
                    "This will send test payloads to the server.\n" +
                    "Confirmed findings will appear in Target → Issues with [AI] Confirmed prefix.",
                "AI Active Scan Started",
                JOptionPane.INFORMATION_MESSAGE,
            ),
            ManualScanDialogs.suggested(SuggestedQueueOutcome.Queued(three.take(1), 2), 2000),
        )
        assertEquals(
            ScanDialog(
                "No suggested targets were queued. They are out of scope, not tested in the current scan mode, " +
                    "or the active scan queue is full (max 2000).",
                "AI Active Scan",
                JOptionPane.WARNING_MESSAGE,
            ),
            ManualScanDialogs.suggested(SuggestedQueueOutcome.Queued(emptyList(), 3), 2000),
        )
        assertEquals(
            ScanDialog(REFUSAL, "AI Active Scan", JOptionPane.WARNING_MESSAGE),
            ManualScanDialogs.suggested(SuggestedQueueOutcome.Refused(REFUSAL), 2000),
        )
    }

    @Test
    fun hostCountCountsDistinctLowerCasedHosts() {
        assertEquals(1, ManualScanDialogs.hostCount(listOf("https://A.example/1", "https://a.example/2")))
        assertEquals(2, ManualScanDialogs.hostCount(listOf("https://A.example/1", "https://a.example/2", "https://b.example/")))
        assertEquals(2, ManualScanDialogs.hostCount(listOf("https://a.example/1", "not a url")))
        assertEquals(3, ManualScanDialogs.hostCount(listOf("https://a.example/1", "not a url", "also not a url")))
    }

    // --- Task 2: refusals, cancellations and partial queues leave the list alone --------------------

    @Test
    fun aRefusalIsShownVerbatimFirstAndNothingElseIsAsked() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
        val scanner = newScanner()
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val prompts = FakePrompts(enable = true, confirm = true)

        val outcome = SuggestedQueueAction(list, scanner, prompts).queue(list.snapshot())

        assertEquals(SuggestedQueueOutcome.Refused(REFUSAL), outcome)
        assertEquals(
            listOf(Call.Show(ScanDialog(REFUSAL, "AI Active Scan", JOptionPane.WARNING_MESSAGE))),
            prompts.calls,
            "the scanner is never offered to be switched on and nothing is confirmed",
        )
        assertEquals(3, list.count())
        assertTrue(scanner.getQueueItems(10).isEmpty())
    }

    @Test
    fun decliningToEnableTheScannerQueuesNothing() {
        val scanner = newScanner()
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val prompts = FakePrompts(enable = false, confirm = true)

        val outcome = SuggestedQueueAction(list, scanner, prompts).queue(list.snapshot())

        assertNull(outcome)
        assertEquals(listOf<Call>(Call.Ensure), prompts.calls)
        assertEquals(3, list.count())
        assertTrue(scanner.getQueueItems(10).isEmpty())
    }

    @Test
    fun answeringNoToTheConfirmationQueuesNothing() {
        val scanner = newScanner()
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val prompts = FakePrompts(enable = true, confirm = false)

        val outcome = SuggestedQueueAction(list, scanner, prompts).queue(list.snapshot())

        assertNull(outcome)
        assertEquals(
            listOf(Call.Ensure, Call.Confirm(ManualScanDialogs.confirmActiveScanMessage(3, 2, 0))),
            prompts.calls,
        )
        assertEquals(3, list.count())
        assertTrue(scanner.getQueueItems(10).isEmpty())
    }

    @Test
    fun anEmptySelectionAsksNothing() {
        val scanner = newScanner()
        val prompts = FakePrompts(enable = true, confirm = true)

        val outcome = SuggestedQueueAction(SuggestedTargetList(), scanner, prompts).queue(emptyList())

        assertNull(outcome)
        assertEquals(listOf(Call.Show(ManualScanDialogs.NO_SUGGESTED_SELECTION)), prompts.calls)
    }

    @Test
    fun anOutOfScopeTargetStaysInTheListAndIsReportedAsNotQueued() {
        whenever(api.scope().isInScope(any())).thenReturn(true)
        whenever(api.scope().isInScope(URL_B)).thenReturn(false)
        val scanner = newScanner { scopeOnly = true }
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val entries = list.snapshot()
        val prompts = FakePrompts(enable = true, confirm = true)

        val outcome = SuggestedQueueAction(list, scanner, prompts).queue(entries)

        assertEquals(SuggestedQueueOutcome.Queued(entries.take(2).map { it.target }, 1), outcome)
        assertEquals(listOf(entries[2].key), list.snapshot().map { it.key }, "only the out-of-scope entry stays")
        val shown = prompts.calls.last() as Call.Show
        assertEquals(ManualScanDialogs.suggested(outcome!!, scanner.maxQueueSize), shown.dialog)
        assertTrue(shown.dialog.message.contains("\n1 suggested target(s) were not queued"), shown.dialog.message)
    }

    @Test
    fun overflowTargetsStayInTheList() {
        val scanner = newScanner { maxQueueSize = 1 }
        val list = listOf(URL_A1, URL_A2, URL_B).suggestedIn(SuggestedTargetList())
        val entries = list.snapshot()

        val outcome = SuggestedQueueAction(list, scanner, FakePrompts(enable = true, confirm = true)).queue(entries)

        assertEquals(SuggestedQueueOutcome.Queued(listOf(entries[0].target), 2), outcome)
        assertEquals(entries.drop(1).map { it.key }, list.snapshot().map { it.key })
        assertEquals(1, scanner.getQueueItems(10).size)
    }

    // --- Task 2: the context menu shares the prompts and the confirmation ---------------------------

    @Test
    fun contextMenuActiveScanUsesTheSharedPromptsAndConfirmation() {
        val source = SourceRoots.packageFile("ui/UiActions.kt").readText(Charsets.UTF_8)

        assertTrue(
            source.contains("= ActiveScanPrompts.ensureActiveScannerEnabled(tab.root, activeAiScanner)"),
            "UiActions' ensureActiveScannerEnabled must delegate to the shared helper",
        )
        assertTrue(source.contains("ActiveScanPrompts.confirmActiveScan("), "the AI Active Scan confirmation uses the shared prompt")
        assertTrue(
            source.contains("ManualScanDialogs.confirmActiveScanMessage("),
            "the AI Active Scan confirmation uses the shared message builder",
        )
        assertTrue(source.contains("ManualScanDialogs.hostCount("), "the AI Active Scan confirmation shows the host count")
    }

    @Test
    fun theConfirmationTitleLivesOnlyInManualScanDialogs() {
        val holders =
            SourceRoots
                .root(SourceRoots.MAIN)
                .walkTopDown()
                .filter { it.isFile && it.extension == "kt" }
                .filter { it.readText(Charsets.UTF_8).contains(ManualScanDialogs.CONFIRM_ACTIVE_SCAN_TITLE) }
                .map { it.name }
                .toList()

        assertEquals(listOf("ManualScanDialogs.kt"), holders)
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private sealed interface Call {
        data object Ensure : Call

        data class Confirm(
            val message: String,
        ) : Call

        data class Show(
            val dialog: ScanDialog,
        ) : Call
    }

    private class FakePrompts(
        private val enable: Boolean,
        private val confirm: Boolean,
    ) : SuggestedQueuePrompts {
        val calls = mutableListOf<Call>()

        override fun show(dialog: ScanDialog) {
            calls += Call.Show(dialog)
        }

        override fun ensureScannerEnabled(): Boolean {
            calls += Call.Ensure
            return enable
        }

        override fun confirm(message: String): Boolean {
            calls += Call.Confirm(message)
            return confirm
        }
    }

    private fun newScanner(configure: ActiveAiScanner.() -> Unit = {}): ActiveAiScanner =
        ActiveAiScanner(
            api = api,
            supervisor = supervisor,
            audit = mock<AuditLogger>(),
            getSettings = { TestSettings.baselineSettings() },
        ).apply {
            scopeOnly = false
            scanMode = ScanMode.FULL
            configure()
        }.also { scanners += it }

    private fun List<String>.suggestedIn(list: SuggestedTargetList): SuggestedTargetList = list.also { it.addAll(map { url -> target(url) }) }

    private fun target(url: String): ActiveScanTarget {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(HttpParameterType.URL)
        whenever(param.name()).thenReturn("id")
        whenever(param.value()).thenReturn("1")

        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        whenever(request.parameters()).thenReturn(listOf(param))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")

        val rr = mock<HttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        return ActiveScanTarget(
            originalRequest = rr,
            injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", "1"),
            vulnHint = VulnHint(VulnClass.SQLI, 50, "suggested"),
            priority = 50,
        )
    }

    private companion object {
        const val URL_A1 = "https://a.example/x"
        const val URL_A2 = "https://a.example/y"
        const val URL_B = "https://b.example/z"
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
    }
}
