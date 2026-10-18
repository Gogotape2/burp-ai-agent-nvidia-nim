package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
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
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * 31-REVIEW IN-06 / Phase 32 — [ActiveAiScanner.tryQueueTarget] returns true only when the target
 * really reached the active queue, so the full build's auto-queue counts and removes only real
 * queues. [ActiveAiScanner.queueTarget] keeps its signature and delegates to it.
 *
 * An enabled scanner starts worker threads that drain the queue at once, so these tests assert on
 * the Boolean and the returned outcome, and read the queue only from a disabled scanner.
 */
class TryQueueTargetTest {
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

    @Test
    fun aDisabledScannerQueuesNothingAndSaysSo() {
        val scanner = newScanner()

        assertFalse(scanner.tryQueueTarget(target("http://example.com/off?id=1")))
        assertTrue(scanner.getQueueItems(10).isEmpty(), "a disabled scanner queues nothing")
    }

    @Test
    fun aRefusingPolicyReturnsFalseAndWritesOnePausedLine() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
        val scanner = newScanner().apply { setEnabled(true) }

        assertFalse(scanner.tryQueueTarget(target("http://example.com/refused/1?id=1")))
        assertFalse(scanner.tryQueueTarget(target("http://example.com/refused/2?id=1")))
        assertEquals(
            1,
            outputLines().count { it.startsWith("[ActiveAiScanner] Paused: ") },
            "the first refusal of the load writes exactly one Paused line",
        )
    }

    @Test
    fun anAllowedScannerReportsOnlyRealQueues() {
        val outOfScopeUrl = "http://outside.example/scope?id=1"
        whenever(api.scope().isInScope(any())).thenReturn(true)
        whenever(api.scope().isInScope(outOfScopeUrl)).thenReturn(false)
        val scanner =
            newScanner().apply {
                scopeOnly = true
                setEnabled(true)
            }
        val valid = target("http://example.com/valid?id=1")

        assertTrue(scanner.tryQueueTarget(valid), "a valid target reaches the queue")
        assertFalse(scanner.tryQueueTarget(valid), "the same target inside the 1-hour window is not queued again")
        assertFalse(
            scanner.tryQueueTarget(target("http://example.com/csrf?id=1", VulnClass.CSRF)),
            "a passive-only class is never queued",
        )
        assertFalse(scanner.tryQueueTarget(target(outOfScopeUrl)), "an out-of-scope URL is never queued")
    }

    @Test
    fun queueTargetDelegatesAndFillsTheWindow() {
        val scanner = newScanner().apply { setEnabled(true) }
        val t = target("http://example.com/delegate?id=1")

        scanner.queueTarget(t)

        assertFalse(scanner.tryQueueTarget(t), "the delegate queued the target and filled the 1-hour window")
    }

    @Test
    fun handQueueIgnoresTheAutoQueueWindow() {
        val scanner = newScanner().apply { setEnabled(true) }
        val t = target("http://example.com/hand?id=1")

        assertTrue(scanner.tryQueueTarget(t))
        val outcome = scanner.queueSuggested(listOf(t))

        assertEquals(SuggestedQueueOutcome.Queued(queued = listOf(t), skipped = 0), outcome)
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private fun newScanner(): ActiveAiScanner =
        ActiveAiScanner(
            api = api,
            supervisor = supervisor,
            audit = mock<AuditLogger>(),
            getSettings = { TestSettings.baselineSettings() },
        ).apply {
            scopeOnly = false
            maxQueueSize = 64
            scanMode = ScanMode.FULL
        }.also { scanners += it }

    private fun target(
        url: String,
        vulnClass: VulnClass = VulnClass.SQLI,
    ): ActiveScanTarget =
        ActiveScanTarget(
            originalRequest = requestResponse(url),
            injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", "1"),
            vulnHint = VulnHint(vulnClass, 50, "suggested"),
            priority = 50,
        )

    private fun requestResponse(url: String): HttpRequestResponse {
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
        return rr
    }

    private fun outputLines(): List<String> {
        val captor = argumentCaptor<String>()
        verify(logging, atLeast(0)).logToOutput(captor.capture())
        return captor.allValues
    }

    private companion object {
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
    }
}
