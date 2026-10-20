package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AutomaticToolApprovalTest {
    @Test
    fun defaultStillAsksForEveryHttpRequest() {
        assertInstanceOf(ToolApprovalOutcome.Ask::class.java, ToolApprovalGate.evaluate("http1_request", ToolApprovalMemory()))
    }

    @Test
    fun optInCoversBothConfirmationTiersWithoutWritingSessionGrants() {
        val memory = ToolApprovalMemory()
        for (tool in listOf("proxy_http_history", "http1_request", "ext:local:test")) {
            val run = assertInstanceOf(ToolApprovalOutcome.Run::class.java, ToolApprovalGate.evaluate(tool, memory, autoApprove = true))
            assertEquals(ToolDecision.AUTO_APPROVED, run.decision)
            assertFalse(memory.isApprovedForSession(tool))
            assertInstanceOf(ToolApprovalOutcome.Ask::class.java, ToolApprovalGate.evaluate(tool, memory, autoApprove = false))
        }
    }

    @Test
    fun explicitSessionDenialIsPreserved() {
        val memory = ToolApprovalMemory()
        ToolApprovalGate.resolve("proxy_http_history", memory, ToolDecision.DENY_SESSION)
        assertInstanceOf(ToolApprovalOutcome.Denied::class.java, ToolApprovalGate.evaluate("proxy_http_history", memory, autoApprove = true))
    }

    @Test
    fun automaticDecisionCannotBeForgedAsACardClick() {
        assertThrows<IllegalArgumentException> {
            ToolApprovalGate.resolve("http1_request", ToolApprovalMemory(), ToolDecision.AUTO_APPROVED)
        }
    }
}
