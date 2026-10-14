package com.six2dez.burp.aiagent.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.scanner.ManualPassiveScanStart
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.util.concurrent.TimeUnit
import javax.swing.JOptionPane

/**
 * Phase 31 gap closure WR-04 / D-01, D-02 — a manual "AI Passive Scan" the AI access policy refuses
 * shows the policy's own refusal text in a warning dialog, on the first refusal of the load and on
 * every later one, and queues nothing. An allowed scan keeps today's success dialog byte for byte.
 * Driven through the real [PassiveAiScanner] and the pure [ManualScanDialogs] mapping.
 */
class ManualPassiveScanDialogTest {
    private val logging = mock<Logging>()
    private val api =
        mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also {
            whenever(it.logging()).thenReturn(logging)
        }
    private val supervisor = mock<AgentSupervisor>()
    private val scanners = mutableListOf<PassiveAiScanner>()

    @AfterEach
    fun tearDown() {
        scanners.forEach { it.shutdown() }
        scanners.clear()
    }

    @Test
    fun refusedManualScanMapsToAWarningCarryingThePolicyText() {
        refuseSavedBackend()
        val scanner = passiveScanner()

        val offered = List(3) { requestResponse("https://target.example/dialog/$it") }
        val start = scanner.startManualScan(offered)
        drain(scanner)

        assertEquals(ManualPassiveScanStart.Refused(REFUSAL), start)
        assertEquals(ScanDialog(REFUSAL, "AI Passive Scan", JOptionPane.WARNING_MESSAGE), ManualScanDialogs.passive(start))
        offered.forEach { verifyNoInteractions(it) }
        verify(supervisor, never()).startOrAttach(any())
        assertFalse(scanner.getManualScanProgress().first, "no manual scan is shown as in progress")
    }

    @Test
    fun secondRefusalInTheSameLoadStillShowsTheWarningButLogsOnce() {
        refuseSavedBackend()
        val scanner = passiveScanner()

        val first = scanner.startManualScan(List(2) { requestResponse("https://target.example/first/$it") })
        val second = scanner.startManualScan(List(2) { requestResponse("https://target.example/second/$it") })
        drain(scanner)

        val warning = ScanDialog(REFUSAL, "AI Passive Scan", JOptionPane.WARNING_MESSAGE)
        assertEquals(ManualPassiveScanStart.Refused(REFUSAL), first)
        assertEquals(ManualPassiveScanStart.Refused(REFUSAL), second)
        assertEquals(warning, ManualScanDialogs.passive(first))
        assertEquals(warning, ManualScanDialogs.passive(second), "the latch limits the log line, not the dialog")
        val pausedLines = outputLines().filter { it.startsWith("[PassiveAiScanner] Paused: ") }
        assertEquals(1, pausedLines.size, "exactly one paused Output line across both refusals: $pausedLines")
    }

    @Test
    fun queuedOutcomeMapsToTheUnchangedSuccessDialog() {
        val expected =
            ScanDialog(
                "Queued 3 request(s) for AI passive analysis.\n\nFindings will appear in Target → Issues with [AI Passive] prefix.",
                "AI Passive Scan Started",
                JOptionPane.INFORMATION_MESSAGE,
            )
        assertEquals(expected, ManualScanDialogs.passive(ManualPassiveScanStart.Queued(3)))
    }

    @Test
    fun intWrapperReturnsZeroOnRefusalAndEmptyListIsQueuedZero() {
        refuseSavedBackend()
        val scanner = passiveScanner()

        assertEquals(0, scanner.manualScan(List(2) { requestResponse("https://target.example/wrapper/$it") }))
        assertEquals(ManualPassiveScanStart.Queued(0), scanner.startManualScan(emptyList()))
        drain(scanner)
        verify(supervisor, never()).startOrAttach(any())
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private fun refuseSavedBackend() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
    }

    private fun passiveScanner(): PassiveAiScanner =
        PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { TestSettings.baselineSettings("lmstudio") }
            .also { scanners += it }

    /** The scanner executor is single-threaded and FIFO: once this barrier ran, every earlier task ran. */
    private fun drain(scanner: PassiveAiScanner) {
        scanner.executor.submit {}.get(10, TimeUnit.SECONDS)
    }

    private fun outputLines(): List<String> {
        val captor = argumentCaptor<String>()
        verify(logging, atLeast(0)).logToOutput(captor.capture())
        return captor.allValues
    }

    private fun requestResponse(url: String): HttpRequestResponse {
        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.bodyToString()).thenReturn("")
        return mock<HttpRequestResponse>().also { whenever(it.request()).thenReturn(request) }
    }

    private companion object {
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
    }
}
