package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Real catalog IDs, not invented names, so every row below exercises the shipped tier table. */
private const val CONFIRM_TOOL = "proxy_http_history"
private const val CONFIRM_EACH_TOOL = "http1_request"

/** One of the ten aliases McpToolExecutor.canonicalToolId collapses onto [CONFIRM_TOOL]. */
private const val CONFIRM_TOOL_ALIAS = "history"

/**
 * Phase 29 (D-16) — the alias half of [ToolApprovalGateTest], moved here verbatim from it.
 *
 * Model-facing aliases are declared by the generic tool provider, which only the full flavor packages:
 * the native tools declare none. So the two methods whose claim is about an ALIAS resolving onto its
 * canonical tool run on the full classpath, with their original generic sample ids. The store-side
 * ToolApprovalGateTest keeps the same two methods on native ids, minus the alias clauses.
 */
class FullToolApprovalGateTest {
    @Test
    fun sessionMemoryIsKeyedOnCanonicalIdNotTheModelString() {
        val memoryA = ToolApprovalMemory()
        val memoryB = ToolApprovalMemory()

        ToolApprovalGate.resolve(CONFIRM_TOOL, memoryA, ToolDecision.APPROVE_SESSION)

        val aliased = ToolApprovalGate.evaluate(CONFIRM_TOOL_ALIAS, memoryA)

        val run =
            assertInstanceOf(
                ToolApprovalOutcome.Run::class.java,
                aliased,
                "The alias '$CONFIRM_TOOL_ALIAS' canonicalises to '$CONFIRM_TOOL', so the session grant " +
                    "must cover it. A gate keyed on the raw model string would re-prompt for a tool the " +
                    "user already approved, and approve a tool it thinks is different (T-22-12).",
            )
        assertEquals(ToolDecision.SESSION_APPROVED, run.decision)

        // D-10's decisive case: an approval granted while reviewing target A must not apply in a new
        // chat about target B. Two chat sessions hold two memories, and they share nothing.
        assertInstanceOf(
            ToolApprovalOutcome.Ask::class.java,
            ToolApprovalGate.evaluate(CONFIRM_TOOL, memoryB),
            "A second chat session must ask again — approvals do not travel between chats.",
        )
        assertTrue(memoryB.approvedSnapshot().isEmpty(), "Approving in one memory must not touch another.")
    }

    @Test
    fun repeatCounterIncrementsPerCanonicalId() {
        val memory = ToolApprovalMemory()

        assertEquals(1, memory.recordRequest(CONFIRM_TOOL), "The first request is the 1st, not the 0th.")
        assertEquals(2, memory.recordRequest(CONFIRM_TOOL))
        assertEquals(
            3,
            memory.recordRequest(CONFIRM_TOOL_ALIAS),
            "An alias must increment its canonical tool's counter. Two counters for one tool would let " +
                "the card read '1st' on the fourth request — the anti-habituation signal inverted.",
        )
        assertEquals(1, memory.recordRequest(CONFIRM_EACH_TOOL), "A different tool counts separately.")
    }
}
