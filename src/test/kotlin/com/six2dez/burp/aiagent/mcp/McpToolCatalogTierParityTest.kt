package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * SEC-06 completeness invariant for [McpToolCatalog].
 *
 * Every expected set below is written as an ENUMERATED LITERAL, never computed from the catalog.
 * That is the entire point: a computed expectation would follow any edit silently, whereas a literal
 * turns promoting a tool to a laxer tier into a deliberate, reviewed diff. This closes the fragility
 * recorded in `.planning/codebase/CONCERNS.md` §"MCP unsafe-tool gate — new tools must opt in",
 * where forgetting to classify a new tool handed it the permissive behaviour by default.
 */
class McpToolCatalogTierParityTest {
    /**
     * The catalog size is asserted, not derived, because the tier sets below are exhaustive
     * partitions of it: 19 AUTO + 27 CONFIRM + 16 CONFIRM_EACH = 62.
     *
     * Note for whoever sees this fail: `grep -c 'McpToolDescriptor('` reports 63, not 62, because it
     * also counts the `data class` declaration line. 62 is the number of construction sites. If this
     * test fails because a tool was added, that is correct and expected — the author must also place
     * the new tool in exactly one of the tier sets below.
     */
    @Test
    fun catalogHasSeventyOneTools() {
        assertEquals(71, McpToolCatalog.all().size)
    }

    @Test
    fun capturedContextRequiresConfirmationBecauseItReadsAdditionalEvidence() {
        val descriptor = McpToolCatalog.all().single { it.id == "context_read" }
        assertEquals(SecTier.CONFIRM, descriptor.secTier)
        assertFalse(descriptor.unsafeOnly)
        assertTrue(descriptor.nativeTool)
    }

    @Test
    fun autoTierIsExactlyTheEnumeratedNineteen() {
        val expected =
            setOf(
                // Pure transforms and decoders — no new data enters model context.
                "status",
                "url_encode",
                "url_decode",
                "base64_encode",
                "base64_decode",
                "random_string",
                "hash_compute",
                "jwt_decode",
                "decode_as",
                "scope_check",
                // Args-only parsers: pure transforms of text the model already holds.
                "insertion_points",
                "params_extract",
                "diff_requests",
                "request_parse",
                "response_parse",
                "find_reflected",
                // Bounded, self-referential reads of the extension's own state.
                "redact_preview",
                "scan_task_status",
                "intruder_attack_status",
                "websocket_connections",
                "ai_backends_list",
            )
        val actual =
            McpToolCatalog
                .all()
                .filter { it.secTier == SecTier.AUTO }
                .map { it.id }
                .toSet()
        assertEquals(
            expected,
            actual,
            "AUTO means the tool runs with no user decision at all (D-02). Adding one is a security " +
                "decision that belongs in ADR-15, not in a catalog edit. A tool qualifies only if it is " +
                "read-only AND bounded output (D-05) — bulk-read tools such as proxy_http_history, " +
                "site_map and scanner_issues are read-only yet must stay CONFIRM.",
        )
    }

    @Test
    fun confirmEachTierIsExactlyTheEnumeratedSixteen() {
        val expected =
            setOf(
                // Sends attacker-influenceable traffic; args are the whole attack surface.
                "http1_request",
                "http2_request",
                "intruder_attack_start",
                "websocket_open",
                "websocket_send",
                // Stages attacker-chosen traffic one click from the wire — ADR-15's "or stage it for
                // one click" clause. Both repeater tools were CONFIRM until Phase 22's verification
                // (WARN-2) measured that they stage a model-authored HttpRequest exactly as
                // intruder_prepare does, so one session grant covered every later call with different
                // request content. The _with_payload variant substitutes model-supplied payloads into
                // that content first, which widens the grant rather than narrowing it.
                "intruder",
                "intruder_prepare",
                "repeater_tab",
                "repeater_tab_with_payload",
                // Starts real Burp activity against a target.
                "scan_audit_start",
                "scan_audit_start_mode",
                "scan_audit_start_requests",
                "scan_crawl_start",
                // Control-bypass and configuration primitives (T-22-04, T-22-05).
                "scope_include",
                "project_options_set",
                "user_options_set",
                "scan_report",
                // Constant tool name, hostile args, straight to a third-party backend (T-22-03).
                "ai_analyze",
                "ai_passive_scan",
            )
        val actual =
            McpToolCatalog
                .all()
                .filter { it.secTier == SecTier.CONFIRM_EACH }
                .map { it.id }
                .toSet()
        assertEquals(
            expected,
            actual,
            "CONFIRM_EACH prompts on every call with no session memory (D-02). Demoting one to " +
                "CONFIRM lets a single session grant cover every later argument set, which is exactly " +
                "the hole these tools must not have.",
        )
    }

    /**
     * Keeps the two axes coherent without making either derivable from the other: `unsafeOnly` is a
     * capability switch, `secTier` is a trust axis (D-01), but nothing that needs Unsafe Mode may
     * ever run with no user decision.
     */
    @Test
    fun noUnsafeToolIsAuto() {
        val byId = McpToolCatalog.all().associateBy { it.id }
        McpToolCatalog.unsafeToolIds().forEach { id ->
            val descriptor = byId[id]
            assertNotNull(descriptor, "unsafeToolIds() returned $id, which is not in the catalog")
            assertNotEquals(
                SecTier.AUTO,
                descriptor!!.secTier,
                "$id is unsafeOnly, so it must never be AUTO — an unsafe tool running with no user " +
                    "decision is the failure this classification exists to prevent.",
            )
        }
    }

    /**
     * D-01's independence claim, demonstrated concretely. `McpToolContext.isUnsafeToolAllowed`
     * returns true for everything once Unsafe Mode is on, so binding the trust boundary to
     * `unsafeOnly` would leave both of these tools completely ungated — they are not `unsafeOnly`
     * at all, yet they ship data to a third-party model (T-22-03, T-22-15).
     */
    @Test
    fun tierIsIndependentOfUnsafeOnly() {
        val byId = McpToolCatalog.all().associateBy { it.id }
        val unsafeIds = McpToolCatalog.unsafeToolIds()

        listOf("ai_analyze", "ai_passive_scan").forEach { id ->
            val descriptor = byId[id]
            assertNotNull(descriptor, "$id is missing from the catalog")
            assertEquals(
                SecTier.CONFIRM_EACH,
                descriptor!!.secTier,
                "$id must be CONFIRM_EACH: constant tool name, hostile args, straight to a third-party backend.",
            )
            assertFalse(
                descriptor.unsafeOnly,
                "$id must NOT be unsafeOnly — it is the concrete proof that secTier is a second, " +
                    "independent axis. If this ever becomes true, pick a different example rather " +
                    "than deleting the assertion.",
            )
            assertFalse(
                unsafeIds.contains(id),
                "$id must be absent from unsafeToolIds(); deriving the trust boundary from that set " +
                    "would leave it ungated.",
            )
        }
    }
}
