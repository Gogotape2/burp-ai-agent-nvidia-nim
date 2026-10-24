package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.HealthCheckResult
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.spy
import org.mockito.kotlin.whenever

class MontoyaRateLimitHealthTest {
    @Test
    fun rateLimitedProviderIsReachableAndDegradedRatherThanOffline() {
        val transport = spy(MontoyaHttpTransport(mock()))
        doReturn(TransportResponse(429, "", false)).whenever(transport).get("https://example.test", emptyMap(), 3000)
        assertTrue(transport.healthCheckGet("https://example.test", emptyMap()) is HealthCheckResult.Degraded)
    }
}
