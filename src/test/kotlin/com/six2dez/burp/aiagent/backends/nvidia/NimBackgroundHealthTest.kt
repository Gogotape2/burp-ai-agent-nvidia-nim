package com.six2dez.burp.aiagent.backends.nvidia

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.backends.BackgroundHealthCheckCapable
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport
import com.six2dez.burp.aiagent.backends.http.TransportResponse
import com.six2dez.burp.aiagent.backends.openai.OpenAiCompatibleBackend
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.spy
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.concurrent.TimeUnit

class NimBackgroundHealthTest {
    @Test
    fun `periodic status never submits generation while explicit test makes one call`() {
        val backend = NvidiaNimBackendFactory().create() as OpenAiCompatibleBackend
        val transport = spy(MontoyaHttpTransport(mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS)))
        doReturn(TransportResponse(200, "{}", true)).whenever(transport).post(any(), any(), any(), any())
        backend.setHealthCheckTransport(transport)
        val background = backend as BackgroundHealthCheckCapable
        val settings = TestSettings.baselineSettings("nvidia-nim").copy(nvidiaNimModel = "z-ai/glm-5.3")
        repeat(100) { assertFalse(background.backgroundHealthCheck(settings).isHealthy) }
        verify(transport, never()).post(any(), any(), any(), any())
        assertTrue(backend.healthCheck(settings).isHealthy)
        repeat(100) { assertTrue(background.backgroundHealthCheck(settings).isHealthy) }
        verify(transport, times(1)).post(any(), any(), any(), any())
        assertFalse(background.backgroundHealthCheck(settings.copy(nvidiaNimModel = NvidiaNimOptions.DEFAULT_MODEL)).isHealthy)
    }

    @Test
    fun `health snapshot is scoped to endpoint model credential and headers and expires`() {
        var now = 0L
        val snapshot = NimHealthSnapshot { now }
        val settings = TestSettings.baselineSettings("nvidia-nim")
        snapshot.record(settings, HealthCheckResult.Healthy)
        assertEquals(HealthCheckResult.Healthy, snapshot.current(settings))
        listOf(
            settings.copy(nvidiaNimUrl = "https://other.example.test"),
            settings.copy(nvidiaNimModel = "other/model"),
            settings.copy(nvidiaNimApiKey = "other-test-key"),
            settings.copy(nvidiaNimHeaders = "X-Test: changed"),
        ).forEach {
            assertFalse(snapshot.current(it).isHealthy)
        }
        now = TimeUnit.MINUTES.toNanos(5)
        assertFalse(snapshot.current(settings).isHealthy)
    }
}
