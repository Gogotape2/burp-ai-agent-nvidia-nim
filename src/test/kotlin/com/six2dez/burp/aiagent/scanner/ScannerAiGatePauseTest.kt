package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.util.concurrent.TimeUnit

/**
 * Phase 31 / D-02, D-07 — the AI scanners respect the "Use AI" gate before any backend start: while
 * the injected policy refuses the saved backend, every offered item is skipped and dropped (no
 * executor submit, no `startOrAttach`, no retry), the first refusal of the load writes exactly one
 * Output line carrying the refusal text, and `getStatus().aiGatePaused` tells the scanner panel.
 *
 * RESEARCH Pitfall 5: the pre-check asks `refusalForSavedBackend`, which answers with no backend
 * running, so the mocked supervisor here is idle and still refuses.
 */
class ScannerAiGatePauseTest {
    private val logging = mock<Logging>()
    private val api =
        mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS).also {
            whenever(it.logging()).thenReturn(logging)
        }
    private val supervisor = mock<AgentSupervisor>()
    private val passiveScanners = mutableListOf<PassiveAiScanner>()

    @AfterEach
    fun tearDown() {
        passiveScanners.forEach { it.shutdown() }
        passiveScanners.clear()
    }

    // --- Passive scanner ---------------------------------------------------------------------------

    @Test
    fun fiftyRefusedPassiveItemsStartNoBackendAndWriteOneOutputLine() {
        refuseSavedBackend()
        val scanner = passiveScanner()
        scanner.setEnabled(true)

        val offered = List(50) { requestResponse("https://target.example/item/$it") }
        offered.forEach { scanner.enqueueForScanCheck(it) }
        drain(scanner)

        verify(supervisor, never()).startOrAttach(any())
        offered.forEach { verifyNoInteractions(it) } // never handed to the scanner executor
        assertEquals(0, scanner.getStatus().requestsAnalyzed, "no analysis ran")
        val refusalLines = outputLines().filter { it.contains(REFUSAL) }
        assertEquals(1, refusalLines.size, "exactly one Output line for 50 refused items: $refusalLines")
        assertTrue(refusalLines.single().startsWith("[PassiveAiScanner] Paused: "), refusalLines.single())
        verify(logging, never()).logToError(any<String>())
    }

    @Test
    fun refusedManualPassiveScanQueuesNothing() {
        refuseSavedBackend()
        val scanner = passiveScanner()

        val offered = List(3) { requestResponse("https://target.example/manual/$it") }
        val queued = scanner.manualScan(offered)
        drain(scanner)

        assertEquals(0, queued, "a refused manual scan queues nothing")
        offered.forEach { verifyNoInteractions(it) }
        assertFalse(scanner.getManualScanProgress().first, "no manual scan is shown as in progress")
        verify(supervisor, never()).startOrAttach(any())
    }

    @Test
    fun passiveStatusIsPausedOnlyWhileOnAndRefused() {
        refuseSavedBackend()
        val scanner = passiveScanner()
        assertFalse(scanner.getStatus().aiGatePaused, "an OFF scanner is not shown as paused")

        scanner.setEnabled(true)
        assertTrue(scanner.getStatus().aiGatePaused, "an ON scanner the policy refuses is paused")

        allowSavedBackend()
        assertFalse(scanner.getStatus().aiGatePaused, "the paused state follows the live policy")
    }

    @Test
    fun allowedPassiveScannerAcceptsNewTrafficWithoutConfirmation() {
        allowSavedBackend()
        val scanner = passiveScanner()
        scanner.setEnabled(true)

        val offered = requestResponse("https://target.example/allowed")
        scanner.enqueueForScanCheck(offered)
        drain(scanner)

        assertFalse(scanner.getStatus().aiGatePaused)
        // D-07: the session switch is the consent; the item is handed to the analysis with no extra step.
        verify(offered, atLeastOnce()).request()
        assertTrue(outputLines().none { it.contains("Paused: ") }, "no paused line while the policy allows the backend")
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private fun refuseSavedBackend() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
    }

    private fun allowSavedBackend() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(null)
    }

    private fun passiveScanner(): PassiveAiScanner =
        PassiveAiScanner(api, supervisor, mock<AuditLogger>()) { TestSettings.baselineSettings("lmstudio") }
            .also { passiveScanners += it }

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
