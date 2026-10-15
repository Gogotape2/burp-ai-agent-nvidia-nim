package com.six2dez.burp.aiagent.lifecycle

import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import com.six2dez.burp.aiagent.App
import com.six2dez.burp.aiagent.BurpAiAgentExtension
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendDiagnostics.RetryEvent
import com.six2dez.burp.aiagent.redact.Redaction
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestMethodOrder
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.Answers
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Phase 33 / D-07, LIFE-02 — App-level load and unload, in the dedicated `unloadLeakTest` JVM.
 *
 * This class lives in package `lifecycle`, which `tasks.test` excludes: App is a process-wide object,
 * the unload sweep stops every pool tracked in the JVM, and the production unload path runs the
 * irreversible `Dispatchers.shutdown()`. `unloadLeakTest` forks one JVM per class, so the first case
 * here really sees an App that was never loaded, and the case that goes through
 * [BurpAiAgentExtension] (the path that shuts the shared coroutines down) is ordered last.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class AppLifecycleProbe {
    @Test
    @Order(1)
    fun shutdownBeforeAnyLoadInThisJvmReturnsWithoutThrowing() {
        // Fresh fork: App.api was never set, so a step failure could only be reported to System.err.
        assertTimeoutPreemptively(Duration.ofSeconds(UNLOAD_SECONDS)) { App.shutdown() }
    }

    @Test
    @Order(2)
    fun aSecondShutdownAfterAPartialLoadTouchesNothing() {
        val (api, errors) = newApi()
        val logging = api.logging()
        // Throw on the load-diagnostics line: the settings store, backend registry, audit logger and chat
        // supervisor exist by then, MCP, the scanners, the AI request logger and MainTab do not.
        doAnswer { invocation ->
            if (invocation.getArgument<String>(0).startsWith("[Diagnostics]")) error("boom")
            null
        }.whenever(logging).logToOutput(anyString())

        val thrown = assertThrows<IllegalStateException> { App.initialize(api) }
        assertEquals("boom", thrown.message)

        assertTimeoutPreemptively(Duration.ofSeconds(UNLOAD_SECONDS)) { App.shutdown() }
        assertTrue(errors.none { it.contains("shutdown failed") }, "a partial load unloads without a failed step: $errors")

        // Sentinels in the global sinks the first shutdown cleared: a second shutdown that ran its steps
        // again would clear them too.
        val truncationSentinel: (String) -> Unit = {}
        val retrySentinel: (RetryEvent) -> Unit = {}
        Redaction.truncationLogger = truncationSentinel
        BackendDiagnostics.retry = retrySentinel
        val loggingCallsBefore = Mockito.mockingDetails(api.logging()).invocations.size
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(1)) { App.shutdown() }

            assertSame(truncationSentinel, Redaction.truncationLogger, "the second shutdown must not run the sink steps")
            assertSame(retrySentinel, BackendDiagnostics.retry, "the second shutdown must not run the sink steps")
            assertEquals(
                loggingCallsBefore,
                Mockito.mockingDetails(api.logging()).invocations.size,
                "the second shutdown must not log anything",
            )
        } finally {
            Redaction.truncationLogger = null
            BackendDiagnostics.retry = null
        }
    }

    /**
     * LIFE-02: the handler is registered before App.initialize runs, a load that throws is cleaned up
     * and the original exception still reaches Burp. Ordered LAST: this path runs the irreversible
     * shared coroutine shutdown.
     */
    @Test
    @Order(LAST)
    fun aLoadThatThrowsIsCleanedUpAndStillReportedToBurp() {
        val (api, errors) = newApi()
        val extension = api.extension()
        doThrow(IllegalStateException("boom")).whenever(extension).setName(any())

        val thrown = assertThrows<IllegalStateException> { BurpAiAgentExtension().initialize(api) }
        assertEquals("boom", thrown.message, "Burp must receive the original exception")

        val handler = argumentCaptor<ExtensionUnloadingHandler>()
        inOrder(extension) {
            verify(extension).registerUnloadingHandler(handler.capture())
            verify(extension).setName(any())
        }
        assertTrue(errors.none { it.contains("shutdown failed") }, "the failed-load cleanup has no failed step: $errors")

        val errorsBefore = errors.size
        assertTimeoutPreemptively(Duration.ofSeconds(1), "the handler after the failed-load cleanup returns at once") {
            handler.firstValue.extensionUnloaded()
        }
        assertEquals(errorsBefore, errors.size, "the second unload writes nothing")
    }

    private fun newApi(): Pair<MontoyaApi, MutableList<String>> {
        // Built BEFORE the whenever() below, or Mockito reports UnfinishedStubbingException.
        val preferences = InMemoryPreferences()
        val errors = CopyOnWriteArrayList<String>()
        val api: MontoyaApi = mock(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(preferences)
        // Read before doAnswer: a deep-stub call inside the stubbing chain is an unfinished stubbing.
        val logging = api.logging()
        doAnswer { invocation ->
            errors += invocation.getArgument<String>(0)
            null
        }.whenever(logging).logToError(anyString())
        return api to errors
    }

    private companion object {
        const val LAST = Int.MAX_VALUE
        const val UNLOAD_SECONDS = 12L
    }
}
