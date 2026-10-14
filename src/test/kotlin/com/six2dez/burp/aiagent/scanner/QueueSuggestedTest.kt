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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.clearInvocations
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever

/**
 * Phase 32 / D-04, D-08 — [ActiveAiScanner.queueSuggested] queues suggested targets on the user's
 * behalf and says exactly what it did: [SuggestedQueueOutcome.Refused] with the AI access policy's
 * text when the policy refuses the saved backend (nothing queued, no target read), otherwise
 * [SuggestedQueueOutcome.Queued] holding exactly the targets that reached the queue.
 *
 * Every scanner here stays disabled, so no worker thread drains the queue while it is read.
 */
class QueueSuggestedTest {
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
    fun refusedPolicyQueuesNothingWritesNothingAndReadsNoTarget() {
        whenever(supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
        val scanner = newScanner()
        val fixtures = (1..3).map { fixture("http://example.com/refused/$it?id=1") }
        val mocks = fixtures.flatMap { listOf(it.requestResponse, it.request) }
        clearInvocations(*mocks.toTypedArray())

        val outcome = scanner.queueSuggested(fixtures.map { it.target })

        verifyNoInteractions(*mocks.toTypedArray())
        assertEquals(SuggestedQueueOutcome.Refused(REFUSAL), outcome)
        assertEquals(REFUSAL, scanner.suggestedQueueRefusal())
        assertTrue(scanner.getQueueItems(10).isEmpty(), "a refused batch queues nothing")
        assertTrue(
            outputLines().none { it.startsWith("[ActiveAiScanner] Suggested targets") },
            "a refused batch writes no queue line",
        )
    }

    @Test
    fun allowedPolicyQueuesEveryValidTargetAndReportsThem() {
        val scanner = newScanner()
        val targets = (1..3).map { fixture("http://example.com/ok/$it?id=1").target }

        val outcome = scanner.queueSuggested(targets)

        assertTrue(outcome is SuggestedQueueOutcome.Queued, "expected Queued, got $outcome")
        outcome as SuggestedQueueOutcome.Queued
        assertEquals(targets.map { it.id }, outcome.queued.map { it.id })
        assertEquals(0, outcome.skipped)
        assertEquals(targets.map { it.id }.toSet(), scanner.getQueueItems(10).map { it.id }.toSet())
        assertEquals(
            listOf("[ActiveAiScanner] Suggested targets: 3 queued by the user"),
            outputLines().filter { it.startsWith("[ActiveAiScanner] Suggested targets") },
        )
        assertEquals(1, outputLines().size, "exactly one Output line, with the count only")
        assertFalse(scanner.getStatus().scanning, "a disabled scanner does not start processing")
        assertNull(scanner.suggestedQueueRefusal())
    }

    @Test
    fun passiveOnlyModeAndScopeFiltersCountAsSkipped() {
        val modeRejected =
            VulnClass.values().first {
                it !in ScanPolicy.PASSIVE_ONLY_VULN_CLASSES && !ScanPolicy.isAllowedForMode(ScanMode.BUG_BOUNTY, it)
            }
        val outOfScopeUrl = "http://outside.example/scope?id=1"
        whenever(api.scope().isInScope(any())).thenReturn(true)
        whenever(api.scope().isInScope(outOfScopeUrl)).thenReturn(false)
        val scanner =
            newScanner().apply {
                scopeOnly = true
                scanMode = ScanMode.BUG_BOUNTY
            }
        val valid = fixture("http://example.com/valid?id=1").target
        val passiveOnly = fixture("http://example.com/csrf?id=1", VulnClass.CSRF).target
        val outsideMode = fixture("http://example.com/mode?id=1", modeRejected).target
        val outOfScope = fixture(outOfScopeUrl).target

        val outcome = scanner.queueSuggested(listOf(valid, passiveOnly, outsideMode, outOfScope))

        assertEquals(SuggestedQueueOutcome.Queued(queued = listOf(valid), skipped = 3), outcome)
    }

    @Test
    fun aFullQueueQueuesWhatFitsAndSkipsTheRest() {
        val scanner = newScanner().apply { maxQueueSize = 1 }
        val targets = (1..3).map { fixture("http://example.com/partial/$it?id=1").target }

        val outcome = scanner.queueSuggested(targets)

        assertTrue(outcome is SuggestedQueueOutcome.Queued, "expected Queued, got $outcome")
        outcome as SuggestedQueueOutcome.Queued
        assertEquals(listOf(targets.first()), outcome.queued)
        assertEquals(2, outcome.skipped)
    }

    @Test
    fun anEmptyBatchQueuesNothingAndWritesNoOutputLine() {
        val scanner = newScanner()

        val outcome = scanner.queueSuggested(emptyList())

        assertEquals(SuggestedQueueOutcome.Queued(emptyList(), 0), outcome)
        assertTrue(outputLines().isEmpty(), "an empty batch writes no Output line")
    }

    // --- Helpers -----------------------------------------------------------------------------------

    private class Fixture(
        val target: ActiveScanTarget,
        val requestResponse: HttpRequestResponse,
        val request: HttpRequest,
    )

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

    private fun fixture(
        url: String,
        vulnClass: VulnClass = VulnClass.SQLI,
    ): Fixture {
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
        val target =
            ActiveScanTarget(
                originalRequest = rr,
                injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "id", "1"),
                vulnHint = VulnHint(vulnClass, 50, "suggested"),
                priority = 50,
            )
        return Fixture(target, rr, request)
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
