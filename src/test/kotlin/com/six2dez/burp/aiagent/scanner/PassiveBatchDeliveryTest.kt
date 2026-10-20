package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PassiveBatchDeliveryTest {
    private val sends = AtomicInteger()
    private val sent = CountDownLatch(1)
    private val settings =
        TestSettings.baselineSettings().copy(
            preferredBackendId = "nvidia-nim",
            passiveAiBatchSize = 3,
            passiveAiPersistentCacheEnabled = false,
        )
    private val supervisor =
        mock<AgentSupervisor>(
            defaultAnswer =
                Answer { call ->
                    if (call.method.name == "send") {
                        sends.incrementAndGet()
                        call.getArgument<(String) -> Unit>(5)("[]")
                        call.getArgument<(Throwable?) -> Unit>(6)(null)
                        sent.countDown()
                        null
                    } else {
                        Answers.RETURNS_DEFAULTS.answer(call)
                    }
                },
        ).also {
            whenever(it.status()).thenReturn(AgentSupervisor.Status("Running", "nvidia-nim"))
            whenever(it.currentSessionId()).thenReturn("batch-test")
            whenever(it.responseWaitTimeoutMs(org.mockito.kotlin.any())).thenReturn(1000L)
        }
    private val scanner =
        PassiveAiScanner(mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS), supervisor, mock<AuditLogger>()) { settings }

    @AfterEach
    fun shutdown() {
        scanner.shutdown()
    }

    @Test
    fun partialBatchFlushesWithoutAnotherIncomingRequest() {
        scanner.setEnabled(true)
        scanner.batchQueue.enqueue(pending())
        assertEquals(1, scanner.getStatus().queueSize)

        assertTrue(sent.await(4, TimeUnit.SECONDS), "The timer must send an expired partial batch without more traffic")
        scanner.executor.submit {}.get(2, TimeUnit.SECONDS)
        assertEquals(1, sends.get())
        assertTrue(scanner.batchQueue.isEmpty())
        assertEquals(1, scanner.getStatus().requestsAnalyzed)
    }

    @Test
    fun budgetPauseHoldsPartialBatchUntilResumed() {
        scanner.setEnabled(true)
        scanner.setBudgetPaused(true)
        scanner.batchQueue.enqueue(pending())

        assertFalse(sent.await(1500, TimeUnit.MILLISECONDS))
        assertEquals(1, scanner.batchQueue.size())
        scanner.setBudgetPaused(false)
        assertTrue(sent.await(4, TimeUnit.SECONDS))
        assertEquals(1, sends.get())
    }

    @Test
    fun disableDiscardsBufferedAutomaticWork() {
        scanner.setEnabled(true)
        scanner.batchQueue.enqueue(pending())
        scanner.setEnabled(false)

        assertTrue(scanner.batchQueue.isEmpty())
        assertFalse(sent.await(1500, TimeUnit.MILLISECONDS))
        assertEquals(0, sends.get())
    }

    @Test
    fun unloadingDoesNotSubmitBufferedRequests() {
        scanner.setEnabled(true)
        scanner.batchQueue.enqueue(pending())
        scanner.shutdown()
        assertTrue(scanner.batchQueue.isEmpty())
        assertEquals(0, sends.get())
    }

    @Test
    fun manualSingleRequestDoesNotWaitForOtherBatchMembers() {
        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn("https://example.test/api/details")
        whenever(request.method()).thenReturn("POST")
        whenever(request.parameters()).thenReturn(emptyList())
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.bodyToString()).thenReturn("x".repeat(120))
        val exchange = mock<HttpRequestResponse>()
        whenever(exchange.request()).thenReturn(request)

        scanner.analyzeManually(exchange)

        assertEquals(1, sends.get())
        assertTrue(scanner.batchQueue.isEmpty())
    }

    private fun pending(): PendingAnalysis =
        PendingAnalysis(
            metadata = "Synthetic local test metadata",
            requestResponse = mock(),
            minSeverity = "LOW",
            host = "example.test",
            enqueuedAtMs = System.currentTimeMillis() - 6_000,
        )
}
