package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ChatPresentationTest {
    @Test
    fun rawToolDataAndRestoredInternalFollowupsAreNotRendered() {
        val payload = "PRIVATE_RESULT_MARKER".repeat(2000)
        val summary = ChatPresentation.visibleText("Tool result: proxy_http_history", payload).orEmpty()
        assertTrue(summary.contains("proxy_http_history"))
        assertFalse(summary.contains("PRIVATE_RESULT_MARKER"))
        assertTrue(summary.length < 200)
        assertNull(ChatPresentation.visibleText("user", "Tool result for proxy_http_history:\n$payload\n\nUser request:\nInspect evidence\n\nProvide the final response using the tool result."))
        assertFalse(ChatPresentation.visibleText("assistant", "Tool result (proxy_http_history):\n$payload").orEmpty().contains("PRIVATE_RESULT_MARKER"))
        assertTrue(ChatPresentation.visibleText("assistant", """{"tool":"proxy_http_history","args":{"count":20,"query":"PRIVATE_RESULT_MARKER"}}""").orEmpty().contains("Данные скрыты"))
    }

    @Test
    fun ordinaryUserTextAndReportsRemainVisible() {
        val report = "Наблюдение: HTTP 403. Пример:\n```json\n{\"tool\":\"http1_request\",\"args\":{}}\n```"
        assertTrue(ChatPresentation.visibleText("assistant", report) == report)
        assertTrue(ChatPresentation.visibleText("user", "Tool result for something is a phrase I want explained.")!!.contains("phrase"))
    }
}
