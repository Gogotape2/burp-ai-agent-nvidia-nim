package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChatExecutionEvidenceTest {
    @Test
    fun practicalRequestsRequireExecutionRatherThanAClaimOrReadOnlyLookup() {
        val evidence = ChatExecutionEvidence("Окей теперь проверь на практике реальна ли уязвимость")
        assertNotNull(evidence.notice())
        evidence.record("proxy_http_history", "Captured evidence")
        evidence.record("scan_audit_start_mode", "Queued", argumentsJson = """{"mode":"PASSIVE"}""")
        assertTrue(evidence.notice().orEmpty().contains("не включали"))
        evidence.record("http1_request", "Error: out of scope")
        assertTrue(evidence.notice().orEmpty().contains("не завершена"))
        evidence.record("http1_request", "HTTP/1.1 403 Forbidden")
        assertNull(evidence.notice(), "A completed request is evidence of execution, not proof of vulnerability")
    }

    @Test
    fun explanationsAndRoutineAnalysisDoNotOfferAnActiveTest() {
        listOf(
            "Как проверить уязвимость на практике?",
            "Explain how to test the target",
            "Составь план проверки",
            "Summarize the supplied response",
            "Декодируй строку",
            "Find the latest vulnerabilities for Apache",
            "Research runtime vulnerabilities",
        ).forEach {
            assertFalse(ChatExecutionEvidence.requestsPracticalCheck(it), it)
        }
        listOf("Начни проверять таргет", "Verify the vulnerability in practice", "Запусти активную проверку").forEach {
            assertTrue(ChatExecutionEvidence.requestsPracticalCheck(it), it)
        }
    }

    @Test
    fun denialIsDistinguishedFromAPlainModelAnswer() {
        val evidence = ChatExecutionEvidence("Проверь уязвимость на практике")
        evidence.recordDenied()
        assertTrue(evidence.notice().orEmpty().contains("не был разрешён"))
    }

    @Test
    fun passiveAndEmptyAuditsDoNotCountAsPracticalVerification() {
        val evidence = ChatExecutionEvidence("Запусти активную проверку")
        evidence.record("scan_audit_start", "Started audit", argumentsJson = """{"builtInConfiguration":"LEGACY_ACTIVE_AUDIT_CHECKS"}""")
        evidence.record("scan_audit_start_mode", "Started audit", argumentsJson = """{"mode":"ACTIVE","requests":[]}""")
        evidence.record("scan_audit_start_requests", "Started audit", argumentsJson = """{"builtInConfiguration":"LEGACY_PASSIVE_AUDIT_CHECKS","requests":["GET / HTTP/1.1"]}""")
        assertNotNull(evidence.notice())
        evidence.record("scan_audit_start_mode", "Started audit with requests", argumentsJson = """{"mode":"ACTIVE","requests":["GET / HTTP/1.1"]}""")
        assertNull(evidence.notice(), "Enqueuing active requests is execution evidence, not proof of a finding")
    }
}
