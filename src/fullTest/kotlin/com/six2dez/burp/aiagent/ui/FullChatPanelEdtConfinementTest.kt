package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.config.AgentSettings
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.AbstractButton
import javax.swing.JButton
import javax.swing.SwingUtilities

/**
 * Phase 29 (D-16) — the CONFIRM_EACH half of [ChatPanelEdtConfinementTest], moved here verbatim.
 *
 * S-09's claim is tier-specific: a superseded CONFIRM_EACH call reaches Burp exactly once. Its own
 * KDoc below records why `scope_include` is the one CONFIRM_EACH tool that both completes headlessly
 * and reaches a stubbable Montoya seam. That tool is a generic one, which only the full flavor
 * packages, and neither native CONFIRM_EACH tool reaches Burp from the chat context (`ai_analyze` and
 * `ai_passive_scan` stop at the absent supervisor). Re-sampling it to a CONFIRM tool would turn the
 * tier-specific claim into a generic one, which the KDoc forbids, so the method runs here on the full
 * classpath with its original sample. The private helpers it uses are copied from the store file
 * unchanged; [ToolLatches] is nested because a second file-private top-level class of the same name
 * in this package would collide with the store file's on the shared test classpath.
 *
 * The class name keeps the store suite's naming constraint: no `*IntegrationTest` / `*ConcurrencyTest`
 * style suffix, so `-PexcludeHeavyTests=true` still runs it.
 */
class FullChatPanelEdtConfinementTest {
    /**
     * S-09 / CFM 2 / T-23-10 — an approved call that is superseded mid-flight executes EXACTLY ONCE.
     *
     * The supersede is a compare-and-set with exactly one winner: whoever takes the token wins, and
     * the returning worker's `clearIfMatches` loses and discards. The failure this rules out is the
     * one that would matter most on a security tool — the resolution path and the worker both
     * proceeding, so a single human `Approve once` click puts two requests on the wire.
     *
     * **A genuine `CONFIRM_EACH` tool, not a `CONFIRM` one approved once.** The two behave alike for a
     * single call, so substituting would have quietly turned a tier-specific claim into a generic one.
     * `scope_include` is the one CONFIRM_EACH tool that both reaches a stubbable Montoya seam and
     * completes headlessly: `http1_request` / `http2_request` die in `HttpRequest.httpRequest`, which
     * `McpScopeFilter.deriveScopeUrl`'s KDoc records as unavailable in pure-JVM unit tests; every
     * `scan_*` one is Professional-only; `ai_analyze` and `ai_passive_scan` need runtime AI
     * dependencies the chat context does not carry. Reaching it costs the settings override below,
     * which is a real user configuration rather than a test hook.
     *
     * The two-button assertion is a SETUP assertion: it fails if `scope_include` ever stops being
     * CONFIRM_EACH, rather than letting this test silently become the CONFIRM case.
     */
    @Test
    fun aSupersededConfirmEachCallReachesBurpExactlyOnce() {
        val latches = ToolLatches()
        val h =
            ChatPanelTestHarness.create(
                modelResponse = toolCall("scope_include", """{"url":"http://s09.example/"}"""),
                settings = settingsEnabling("scope_include"),
            )
        // Resolved to a local FIRST. `includeInScope` returns void, so the stub has to be written
        // `doAnswer {}.whenever(mock)`, and leaving the deep-stub `h.api.scope()` call inside the
        // `whenever(...)` argument makes Mockito read THAT call as the one being stubbed —
        // UnfinishedStubbingException, measured.
        val scope = h.api.scope()
        doAnswer {
            latches.entered.countDown()
            check(latches.probeRan.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS)) {
                "The test never released the blocked tool — the supersede window was never opened."
            }
            null
        }.whenever(scope).includeInScope(any<String>())

        val traceIdRef = AtomicReference<String>()
        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            ChatPanelTestHarness.sendUserMessage(h, "add that host to scope")
            ChatPanelTestHarness.drainEdt()
            val card = requireNotNull(ChatPanelTestHarness.findApprovalCard(h.panel.root)) { NO_CARD }
            assertEquals(
                listOf("Deny", "Approve once"),
                decisionButtons(card).map { it.text },
                "Setup: this scenario is about CONFIRM_EACH. Two actions is what that tier offers; four " +
                    "would mean the tool was re-tiered and this test now proves something else.",
            )
            traceIdRef.set(pendingTraceId(h))
            click(card, "Approve once")
            assertTrue(
                latches.entered.await(HANDSHAKE_FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "The tool worker never started, so there was nothing to supersede.",
            )

            SwingUtilities.invokeAndWait { cancelButton(h).doClick() }

            latches.probeRan.countDown()
            ChatPanelTestHarness.awaitToolSettled(label = traceIdRef.get(), count = 1)
        }

        // THE CLAIM. One click, one call on the wire — read from the Montoya double the tool body
        // actually reached, not from a counter this test keeps.
        verify(scope, times(1)).includeInScope(any<String>())
        // And the loser of the compare-and-set does not re-enter later: drained well past the point a
        // second dispatch would have landed.
        ChatPanelTestHarness.drainEdt(times = LONG_DRAIN)
        verify(scope, times(1)).includeInScope(any<String>())

        val record = decisionsFor(traceIdRef.get()).single()
        assertEquals(
            ChatPanel.SUPERSEDED_RUN_STATUS,
            record["status"],
            "The superseded call is still audited — it reached Burp and cannot be recalled (D-07).",
        )
        assertEquals("approve_once", record["decision"], "The decision the human really made is unchanged by the supersede.")
        assertOrderedAuditPair(h, record, traceIdRef.get(), extraKeys = setOf(SUPERSEDE_REASON_KEY))
    }

    // ── Audit + worker capture plumbing (copied from ChatPanelEdtConfinementTest) ──────

    private val auditEvents = CopyOnWriteArrayList<Pair<String, Map<*, *>>>()

    /**
     * Every SC3 decision record belonging to [traceId], in emission order.
     *
     * The trace id is the ONLY sound selector here: `AuditLogger.registerGlobalEmitter` is a
     * process-global hook, panels built by earlier tests in this class are never shut down, and their
     * queued `invokeLater` chains run on this test's drains. Filtering by tool name or reading
     * positionally would silently fold in another chain's events.
     */
    private fun decisionsFor(traceId: String): List<Map<*, *>> = auditEvents.filter { it.first == TOOL_DECISION_EVENT && it.second["traceId"] == traceId }.map { it.second }

    @BeforeEach
    fun installObservers() {
        auditEvents.clear()
        AuditLogger.registerGlobalEmitter { type, payload ->
            if (payload is Map<*, *>) auditEvents += type to payload
        }
        ChatPanelTestHarness.installSettledObserver()
    }

    @AfterEach
    fun releaseObservers() {
        // Both are process-global singleton hooks. Left registered, this class would capture — and hold
        // — events emitted by every test class that runs after it. Same discipline as
        // ChatPanelToolGateTest.kt:649-654, and for the same reason.
        AuditLogger.registerGlobalEmitter(null)
        ChatPanelTestHarness.releaseSettledObserver()
    }

    /** The two halves of the SC3 mutual handshake, named so the test body reads as the protocol it is. */
    private class ToolLatches {
        /** Counted down by the tool double the instant its body is entered. */
        val entered = CountDownLatch(1)

        /** Counted down from a runnable the test queues to the EDT; the tool double waits on it. */
        val probeRan = CountDownLatch(1)
    }
}

// ── Helpers (copied unchanged from ChatPanelEdtConfinementTest) ─────────────────────────

private const val NO_CARD = "No ToolApprovalCard in the transcript — the SEC-06 gate did not raise a decision."

/**
 * Comfortably longer than any followup this suite drives after a decision click; over-draining an
 * empty EDT queue is free, and under-draining would leave the denial's followup turn unsent.
 */
private const val LONG_DRAIN = 24

/** The `AuditLogger` event type every SC3 decision record is emitted under. */
private const val TOOL_DECISION_EVENT = "mcp_tool_decision"

/**
 * Deadlock failsafe for the SC3 handshake, in seconds.
 *
 * A bound on a hang, never a threshold the work is measured against: nothing compares an elapsed
 * duration to it. Ten and not sixty because a red-before-green run against the pre-fix tree pays it in
 * full, once, and ten seconds is the budgeted price of that demonstration.
 */
private const val HANDSHAKE_FAILSAFE_SECONDS = 10L

/**
 * The trace id of the single parked decision, read reflectively off the live panel.
 *
 * Same helper, and the same reason, as `ChatPanelToolGateTest.kt:818`: every audit assertion needs a
 * selector that is this chain's alone, and the trace id is the only field that qualifies.
 */
private fun pendingTraceId(h: ChatPanelTestHarness.Harness): String {
    lateinit var traceId: String
    SwingUtilities.invokeAndWait {
        val field = ChatPanel::class.java.getDeclaredField("pendingDecisions")
        field.isAccessible = true
        val pending = field.get(h.panel) as Map<*, *>
        val record = requireNotNull(pending.values.singleOrNull()) { "Expected exactly one parked decision; found ${pending.keys}." }
        val slot = record.javaClass.getDeclaredField("traceId").also { it.isAccessible = true }
        traceId = slot.get(record) as String
    }
    return traceId
}

/** The panel's real Cancel button — the affordance UI-SPEC Rule S-5 says must not be inert in S3. */
private fun cancelButton(h: ChatPanelTestHarness.Harness): JButton =
    requireNotNull(ChatPanelTestHarness.find(h.panel.root, JButton::class.java) { it.text == "Cancel" }) {
        "No JButton labelled 'Cancel' under ChatPanel.root — Rule C-1 pins that label, so a miss here " +
            "means it was renamed."
    }

/**
 * The extra metadata key `discardSupersededToolResult` merges onto the reporter's map.
 *
 * Named here so [assertOrderedAuditPair] can subtract it before comparing the two records, rather
 * than having each caller restate the string.
 */
private const val SUPERSEDE_REASON_KEY = "supersedeReason"

/**
 * AI-SPEC E4 — the audit PAIR for one call, asserted as the DATA DEPENDENCY it actually is.
 *
 * `toolDecisionReporter.report` emits the `mcp_tool_decision` event AND returns the null-filtered copy
 * of that same payload; `supervisor.aiRequestLogger?.log` then consumes what it returned. So "report
 * ran first" is not a convention to be checked by call order — it is provable from the data, and this
 * checks it there: the AI-activity metadata must BE the decision payload, minus its null values and
 * plus [extraKeys]. A `log` call that assembled its own map, or one made with a stale one, fails this
 * and would pass an ordering check.
 *
 * Both sides are selected by trace id and never by list position: `AuditLogger`'s emitter is
 * process-global and panels built by earlier tests in this class are still alive.
 */
private fun assertOrderedAuditPair(
    h: ChatPanelTestHarness.Harness,
    decision: Map<*, *>,
    traceId: String,
    extraKeys: Set<String>,
) {
    val logged = loggedMetadataFor(h, traceId)
    val reported = decision.entries.filter { it.value != null }.associate { it.key.toString() to it.value.toString() }
    assertEquals(
        reported,
        logged - extraKeys,
        "E4: the AI-activity record must be exactly what the decision reporter returned. A record that " +
            "merely LOOKS right but was built separately would drift from the audit event the first time " +
            "either shape changed, and the two sinks would then disagree about the same call.",
    )
    extraKeys.forEach { key ->
        assertTrue(
            logged.containsKey(key),
            "The '$key' key must ride along on the AI-activity record; the pair carried ${logged.keys}.",
        )
    }
}

/**
 * The metadata map handed to `AiRequestLogger.log` for [traceId].
 *
 * `log` takes ten parameters and every one is matched positionally, so the captor lines up with the
 * last. `singleOrNull` is itself an assertion: exactly one AI-activity record per call is the other
 * half of "exactly one audit pair per exit".
 */
private fun loggedMetadataFor(
    h: ChatPanelTestHarness.Harness,
    traceId: String,
): Map<String, String> {
    val metadata = argumentCaptor<Map<String, String>>()
    verify(requireNotNull(h.supervisor.aiRequestLogger) { "No AiRequestLogger on the supervisor double." }, atLeast(1)).log(
        any(),
        any(),
        any(),
        any(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        anyOrNull(),
        metadata.capture(),
    )
    return requireNotNull(metadata.allValues.singleOrNull { it["traceId"] == traceId }) {
        "Expected exactly one AI-activity record for trace $traceId; captured ${metadata.allValues.map { it["traceId"] }}."
    }
}

/**
 * Baseline settings with [toolIds] switched on, unsafe mode included.
 *
 * A real user configuration rather than a test hook: every `CONFIRM_EACH` tool that both completes
 * headlessly and touches a stubbable Montoya seam is `unsafeOnly` and off by default, so reaching that
 * tier at all requires the same two toggles a user would set in the MCP settings tab.
 */
private fun settingsEnabling(vararg toolIds: String): AgentSettings {
    val base = TestSettings.baselineSettings()
    return base.copy(
        mcpSettings =
            base.mcpSettings.copy(
                unsafeEnabled = true,
                toolToggles = toolIds.associateWith { true },
            ),
    )
}

/** The four D-11 labels, defined once so "is this a decision button?" is asked one way. */
private val DECISION_LABELS = setOf("Deny", "Deny for session", "Approve once", "Approve for session")

/** The fenced payload shape `ToolCallParser.extractFirst` resolves (ToolCallParser.kt:80-108). */
private fun toolCall(
    tool: String,
    argsJson: String,
): String =
    """
    ```json
    {"tool":"$tool","args":$argsJson}
    ```
    """.trimIndent()

private fun allDescendants(root: Container): List<Component> =
    root.components.flatMap { child ->
        listOf(child) + if (child is Container) allDescendants(child) else emptyList()
    }

private fun decisionButtons(root: Container): List<AbstractButton> = allDescendants(root).filterIsInstance<AbstractButton>().filter { it.text in DECISION_LABELS }

/** Clicks a decision button on the EDT, exactly as the AWT event pump would dispatch it. */
private fun click(
    card: Container,
    label: String,
) {
    val button =
        requireNotNull(decisionButtons(card).firstOrNull { it.text == label }) {
            "No '$label' button on the card. Present: ${decisionButtons(card).map { it.text }}"
        }
    SwingUtilities.invokeAndWait { button.doClick() }
}
