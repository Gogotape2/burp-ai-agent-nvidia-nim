package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Real catalog IDs, not invented names, so every row below exercises the shipped tier table.
 *
 * Phase 29 (D-16): native tools (NativeTools.kt), so the store build, which ships only those, runs
 * every row. The alias rows need the generic provider's alias table and run in FullToolApprovalGateTest.
 */
private const val AUTO_TOOL = "status"
private const val CONFIRM_TOOL = "issue_create"
private const val CONFIRM_EACH_TOOL = "ai_analyze"

/**
 * Mirrors `ChatPanel.MAX_AUTO_TOOL_ITERATIONS`. Every expectation below is DERIVED from
 * it rather than written out, so raising or lowering the real budget cannot leave a stale literal here
 * quietly passing.
 */
private const val MAX_AUTO_TOOL_ITERATIONS = 8

/** Steps taken past zero, to prove the budget saturates instead of going negative. */
private const val STEPS_PAST_ZERO = 2

/** Enough repeats that a session set accumulating even once would be caught. */
private const val CONFIRM_EACH_REPEATS = 20

/**
 * SC2 and SC4 for the SEC-06 decision core: the three-tier state machine, the four clickable actions,
 * per-session memory keyed on canonical IDs, D-12's denial constant, and D-13's monotone budget.
 *
 * No mock appears here and none is needed — the gate is pure, so every assertion runs with no Burp API,
 * no Swing harness and no clock. That is the whole reason the policy lives in an AWT-free file: the
 * `.planning/codebase/CONCERNS.md` gap that let SEC-04 ship green was UI-layer behaviour with no
 * assertable seam, and the answer is to put the decision where a unit test can reach it.
 */
class ToolApprovalGateTest {
    // -------------------------------------------------------------------------------------------
    // D-02 — three tiers, three distinct pre-card behaviours
    // -------------------------------------------------------------------------------------------

    @Test
    fun autoTierRunsWithNoDecision() {
        val memory = ToolApprovalMemory()

        val outcome = ToolApprovalGate.evaluate(AUTO_TOOL, memory)

        val run =
            assertInstanceOf(
                ToolApprovalOutcome.Run::class.java,
                outcome,
                "An AUTO tool must run with no card and no human decision (D-02).",
            )
        assertEquals(ToolDecision.AUTO, run.decision)
        assertEquals(SecTier.AUTO, run.tier)
        // An AUTO call is not a grant: it must leave no trace in either session set, or the first
        // silent tool call of a chat would start populating memory nobody consented to.
        assertTrue(memory.approvedSnapshot().isEmpty(), "AUTO must not write the approved set.")
        assertTrue(memory.deniedSnapshot().isEmpty(), "AUTO must not write the denied set.")
    }

    @Test
    fun confirmTierAsksWithFourActions() {
        val memory = ToolApprovalMemory()

        val outcome = ToolApprovalGate.evaluate(CONFIRM_TOOL, memory)

        val ask =
            assertInstanceOf(
                ToolApprovalOutcome.Ask::class.java,
                outcome,
                "A CONFIRM tool with no prior decision must prompt.",
            )
        assertEquals(SecTier.CONFIRM, ask.tier)
        assertEquals(CONFIRM_TOOL, ask.canonicalId)
        assertTrue(
            ask.offersSessionActions,
            "D-11: CONFIRM offers all four actions. The flag is computed by the gate precisely so the " +
                "card cannot re-derive it from the tier and get it wrong.",
        )
    }

    @Test
    fun confirmEachTierAsksWithTwoActions() {
        val memory = ToolApprovalMemory()

        val outcome = ToolApprovalGate.evaluate(CONFIRM_EACH_TOOL, memory)

        val ask =
            assertInstanceOf(
                ToolApprovalOutcome.Ask::class.java,
                outcome,
                "A CONFIRM_EACH tool must prompt on every call.",
            )
        assertEquals(SecTier.CONFIRM_EACH, ask.tier)
        assertFalse(
            ask.offersSessionActions,
            "D-02/D-11: CONFIRM_EACH shows only Approve once / Deny. Offering a session action here is " +
                "T-22-18 — one click handing the model unlimited traffic-generating tools.",
        )
    }

    // -------------------------------------------------------------------------------------------
    // D-11 — the four clickable actions, and what each one remembers
    // -------------------------------------------------------------------------------------------

    @Test
    fun approveOnceRunsButDoesNotRemember() {
        val memory = ToolApprovalMemory()

        val resolved = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.APPROVE_ONCE)

        val run =
            assertInstanceOf(
                ToolApprovalOutcome.Run::class.java,
                resolved,
                "Approve once must let this call proceed.",
            )
        assertEquals(ToolDecision.APPROVE_ONCE, run.decision)
        assertTrue(memory.approvedSnapshot().isEmpty(), "Approve once is per-call by definition.")
        assertInstanceOf(
            ToolApprovalOutcome.Ask::class.java,
            ToolApprovalGate.evaluate(CONFIRM_TOOL, memory),
            "A second call to the same tool must prompt again — otherwise Approve once and Approve for " +
                "session are the same button with two labels.",
        )
    }

    @Test
    fun approveForSessionSuppressesTheNextCard() {
        val memory = ToolApprovalMemory()

        val resolved = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.APPROVE_SESSION)

        val clicked =
            assertInstanceOf(ToolApprovalOutcome.Run::class.java, resolved, "Approve for session must run this call.")
        assertEquals(ToolDecision.APPROVE_SESSION, clicked.decision)

        val next = ToolApprovalGate.evaluate(CONFIRM_TOOL, memory)

        val suppressed =
            assertInstanceOf(
                ToolApprovalOutcome.Run::class.java,
                next,
                "The session grant must suppress the second card.",
            )
        // The distinction is what lets an auditor see whether a human clicked FOR THIS CALL. Collapsing
        // APPROVE_SESSION and SESSION_APPROVED into one "approved" token makes "did anyone actually see
        // this invocation?" unanswerable from the record (T-22-22).
        assertEquals(
            ToolDecision.SESSION_APPROVED,
            suppressed.decision,
            "The suppressed call must record SESSION_APPROVED, not APPROVE_SESSION — no human saw it.",
        )
    }

    @Test
    fun denyForSessionResolvesLaterCallsInstantlyWithNoCard() {
        val memory = ToolApprovalMemory()

        val resolved = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.DENY_SESSION)

        val clicked =
            assertInstanceOf(ToolApprovalOutcome.Denied::class.java, resolved, "Deny for session must refuse this call.")
        assertEquals(ToolDecision.DENY_SESSION, clicked.decision)

        val next = ToolApprovalGate.evaluate(CONFIRM_TOOL, memory)

        // SC4's second clause: the retry loop is bounded STRUCTURALLY here, not by the iteration
        // counter. A model that re-emits a session-denied tool never produces a second card.
        assertFalse(
            next is ToolApprovalOutcome.Ask,
            "A session-denied tool must never prompt again — that is the mechanism SC4's second clause " +
                "relies on (D-11).",
        )
        val suppressed =
            assertInstanceOf(
                ToolApprovalOutcome.Denied::class.java,
                next,
                "A session-denied tool must resolve instantly as denied.",
            )
        assertEquals(ToolDecision.SESSION_DENIED, suppressed.decision)
    }

    @Test
    fun confirmEachNeverGainsSessionMemory() {
        val memory = ToolApprovalMemory()

        repeat(CONFIRM_EACH_REPEATS) { index ->
            ToolApprovalGate.resolve(CONFIRM_EACH_TOOL, memory, ToolDecision.APPROVE_ONCE)
            assertInstanceOf(
                ToolApprovalOutcome.Ask::class.java,
                ToolApprovalGate.evaluate(CONFIRM_EACH_TOOL, memory),
                "After ${index + 1} approvals, a CONFIRM_EACH tool must STILL prompt. D-02's third tier " +
                    "exists precisely so repetition cannot be short-circuited into a standing grant.",
            )
        }
        assertTrue(memory.approvedSnapshot().isEmpty(), "CONFIRM_EACH must write to neither session set.")
        assertTrue(memory.deniedSnapshot().isEmpty(), "CONFIRM_EACH must write to neither session set.")

        // The card never offers these two for this tier, so a caller passing one has a bug the gate
        // surfaces rather than absorbs.
        assertThrows(IllegalArgumentException::class.java) {
            ToolApprovalGate.resolve(CONFIRM_EACH_TOOL, memory, ToolDecision.APPROVE_SESSION)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ToolApprovalGate.resolve(CONFIRM_EACH_TOOL, memory, ToolDecision.DENY_SESSION)
        }
    }

    // -------------------------------------------------------------------------------------------
    // D-12 — one fixed, neutral, deterministic denial result
    // -------------------------------------------------------------------------------------------

    @Test
    fun denialResultIsFixedNeutralAndNotErrorPrefixed() {
        val memory = ToolApprovalMemory()

        // Ordered so the two non-writing actions run before DENY_SESSION populates the denied set.
        val perCall = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.DENY)
        val implicit = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.IMPLICIT_DENY)
        val forSession = ToolApprovalGate.resolve(CONFIRM_TOOL, memory, ToolDecision.DENY_SESSION)
        val suppressed = ToolApprovalGate.evaluate(CONFIRM_TOOL, memory)

        val results =
            listOf(perCall, implicit, forSession, suppressed).map { outcome ->
                assertInstanceOf(
                    ToolApprovalOutcome.Denied::class.java,
                    outcome,
                    "Every denial path must produce a Denied outcome.",
                ).result
            }
        results.forEach { result ->
            assertEquals(
                ToolApprovalGate.DENIAL_RESULT,
                result,
                "All four denial decisions must return the SAME constant byte for byte. If the text " +
                    "varied, the model could tell whether a human clicked, an earlier click was applied, " +
                    "or nobody answered — and tune its retry accordingly.",
            )
        }
        assertEquals(1, results.toSet().size, "Four denial decisions, one string.")

        // D-12: the tool-chain telemetry in ChatPanel.executeApprovedToolCall derives status = "error"
        // from this prefix.
        // A refusal is a policy outcome, not a malfunction; conflating them invites a retry with
        // different args and records a failure where a human made a decision (T-22-19).
        assertFalse(
            ToolApprovalGate.DENIAL_RESULT.startsWith("Error:"),
            "The denial constant must never carry the Error: prefix — it would be logged as a tool " +
                "failure and read by the model as something that broke.",
        )
        assertTrue(ToolApprovalGate.DENIAL_RESULT.isNotBlank(), "A blank refusal tells the model nothing.")
    }

    // -------------------------------------------------------------------------------------------
    // D-13 / SC4 — the budget is monotone, terminates, and does not depend on what was clicked
    // -------------------------------------------------------------------------------------------

    @Test
    fun iterationBudgetIsMonotoneAndTerminates() {
        val approvals = budgetWalk(ToolDecision.APPROVE_ONCE)
        val denials = budgetWalk(ToolDecision.DENY)

        // Derived from MAX_AUTO_TOOL_ITERATIONS, never written out: 7, 6, ... 1, 0, then saturated.
        val expected = (MAX_AUTO_TOOL_ITERATIONS - 1 downTo 0).toList() + List(STEPS_PAST_ZERO) { 0 }
        assertEquals(expected, approvals, "The budget must fall one per call and stop at zero.")

        // SC4 clause 1: exactly MAX_AUTO_TOOL_ITERATIONS steps reach zero, so the chain terminates.
        assertEquals(
            0,
            approvals[MAX_AUTO_TOOL_ITERATIONS - 1],
            "Exactly $MAX_AUTO_TOOL_ITERATIONS steps must exhaust the budget.",
        )
        assertTrue(
            approvals.take(MAX_AUTO_TOOL_ITERATIONS).zipWithNext().all { (before, after) -> after < before },
            "The budget must strictly decrease until it reaches zero — no step may be free.",
        )
        assertTrue(approvals.none { it < 0 }, "The budget must saturate at zero, never go negative.")

        // SC4 clause 2, the half that matters for denials: refusing costs exactly what approving costs.
        // If a denial were free, injected traffic could walk the model through 59 DIFFERENT tools and
        // produce 59 cards — a denial of service delivered through the safety control itself (T-22-08).
        assertEquals(
            approvals,
            denials,
            "D-13: the decrement must not depend on the decision. A denied call consumes one iteration, " +
                "exactly like an approved one.",
        )

        // The two helpers reproduce the followup arguments ChatPanel.denyToolCall and
        // ChatPanel.executeApprovedToolCall pass, so the denial branch and the success
        // branch provably share one decrement rather than two expressions that agree today.
        assertFalse(ToolApprovalGate.allowsFurtherToolCalls(1), "One iteration left means this is the last call.")
        assertTrue(ToolApprovalGate.allowsFurtherToolCalls(2), "Two left means another tool call may follow.")
        assertEquals(0, ToolApprovalGate.nextIterationBudget(0), "Zero must stay zero.")
    }

    // -------------------------------------------------------------------------------------------
    // D-10 — memory is keyed on the canonical ID and dies with the chat session
    // -------------------------------------------------------------------------------------------

    @Test
    fun sessionMemoryIsKeyedOnCanonicalIdNotTheModelString() {
        val memoryA = ToolApprovalMemory()
        val memoryB = ToolApprovalMemory()

        ToolApprovalGate.resolve(CONFIRM_TOOL, memoryA, ToolDecision.APPROVE_SESSION)

        // Phase 29 (D-16): the alias clause needs the generic provider's alias table (native tools
        // declare no aliases) and runs verbatim in FullToolApprovalGateTest. The grant still covers the
        // canonical id itself.
        val run =
            assertInstanceOf(
                ToolApprovalOutcome.Run::class.java,
                ToolApprovalGate.evaluate(CONFIRM_TOOL, memoryA),
                "The session grant must cover the next call to '$CONFIRM_TOOL'.",
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
        // Phase 29 (D-16): the alias-increments-its-canonical-counter clause needs the generic provider's
        // alias table and runs verbatim in FullToolApprovalGateTest.
        assertEquals(1, memory.recordRequest(CONFIRM_EACH_TOOL), "A different tool counts separately.")
    }

    /**
     * Walks the budget from [MAX_AUTO_TOOL_ITERATIONS] down, resolving every step with [action], and
     * returns the budget observed after each step.
     *
     * Uses a CONFIRM_EACH tool because both `APPROVE_ONCE` and `DENY` are legal for it, so the approval
     * walk and the denial walk differ in exactly one thing: the decision.
     */
    private fun budgetWalk(action: ToolDecision): List<Int> {
        val memory = ToolApprovalMemory()
        var remaining = MAX_AUTO_TOOL_ITERATIONS
        return List(MAX_AUTO_TOOL_ITERATIONS + STEPS_PAST_ZERO) {
            ToolApprovalGate.resolve(CONFIRM_EACH_TOOL, memory, action)
            remaining = ToolApprovalGate.nextIterationBudget(remaining)
            remaining
        }
    }
}
