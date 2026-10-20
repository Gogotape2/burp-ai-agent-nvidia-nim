package com.six2dez.burp.aiagent.supervisor

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.mcp.tools.RecordingAnalysisConnection
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.Executors

class ToolAnalysisSessionTest {
    @Test
    fun nimToolLaunchDoesNotReplaceTheRunningScannerSession() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = mock<BackendRegistry>()
        whenever(registry.listAllBackendIds()).thenReturn(emptyList())
        val backend = mock<AiBackend>()
        val scannerConnection = RecordingAnalysisConnection()
        val toolConnection = RecordingAnalysisConnection()
        whenever(registry.get("nvidia-nim")).thenReturn(backend)
        whenever(backend.launch(any())).thenReturn(scannerConnection, toolConnection)
        val pool = Executors.newSingleThreadExecutor()
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), pool)
        try {
            supervisor.applySettings(TestSettings.baselineSettings("nvidia-nim").copy(nvidiaNimTimeoutSeconds = 900))
            assertTrue(supervisor.startOrAttach("nvidia-nim"))
            val scannerSessionId = supervisor.currentSessionId()
            val analysis = supervisor.openToolAnalysisSession()
            assertSame(toolConnection, analysis.connection)
            assertNotSame(scannerConnection, analysis.connection)
            assertEquals(905_000L, analysis.waitTimeoutMs)
            analysis.connection.stop()
            assertTrue(scannerConnection.isAlive())
            assertEquals(scannerSessionId, supervisor.currentSessionId())
            assertEquals("Running", supervisor.status().state)
        } finally {
            supervisor.shutdown()
            pool.shutdownNow()
        }
    }

    @Test
    fun nativeBurpAiStillRequiresItsOwnPermission() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        val registry = mock<BackendRegistry>()
        whenever(registry.listAllBackendIds()).thenReturn(emptyList())
        val pool = Executors.newSingleThreadExecutor()
        val supervisor = AgentSupervisor(api, registry, mock<AuditLogger>(), pool)
        try {
            supervisor.applySettings(TestSettings.baselineSettings("burp-ai"))
            assertThrows<IllegalStateException> { supervisor.openToolAnalysisSession() }
        } finally {
            supervisor.shutdown()
            pool.shutdownNow()
        }
    }
}
