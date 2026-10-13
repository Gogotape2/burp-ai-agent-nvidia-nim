package com.six2dez.burp.aiagent.agents

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

/**
 * Phase 31 / D-17 (TOOL-01, T-31-28) — the bundled agent profiles name only native tools.
 *
 * The profiles are one file per name at one resource path in both builds (per-flavor copies would collide
 * in the fat JAR), so they must not steer the store build's model toward tools its catalog does not hold.
 * The full build's model still learns its generic tools from the tool catalog preamble. [GENERIC_TOOL_IDS]
 * is listed literally here; FullBundledProfileToolNamesTest (src/fullTest) proves it equals the full
 * catalog minus [NATIVE_IDS], so the list cannot go stale.
 *
 * Closes the ADR-18 residual deferred to this phase (31-RESEARCH Open Question 3).
 */
class BundledProfileToolNamesTest {
    @AfterEach
    fun tearDown() {
        AgentProfileLoader.setBaseDirForTests(null)
    }

    @Test
    fun noBundledProfileNamesAGenericTool() {
        val hits = PROFILES.flatMap { name -> genericToolHits("$name.md", bundledText(name)) }
        assertEquals(emptyList<String>(), hits, "generic tool ids named in the bundled profiles")
    }

    @Test
    fun everySnakeCaseWordInABundledProfileIsANativeToolId() {
        val strays =
            PROFILES.flatMap { name ->
                SNAKE_CASE_WORD
                    .findAll(bundledText(name))
                    .map { it.value }
                    .filter { it !in NATIVE_IDS }
                    .map { "$name.md: $it" }
                    .toList()
            }
        assertEquals(emptyList<String>(), strays, "snake_case words that are not native tool ids")
    }

    @Test
    fun theLoaderReportsNoMissingToolForAnyBundledProfileAgainstTheStoreCatalog(
        @TempDir home: Path,
    ) {
        AgentProfileLoader.setBaseDirForTests(home)
        AgentProfileLoader.ensureBundledProfilesInstalled()

        PROFILES.forEach { name ->
            assertTrue(Files.exists(home.resolve("$name.md")), "$name.md was not installed into the temp directory")
            assertEquals(
                emptyList<String>(),
                AgentProfileLoader.validateProfile(name, NATIVE_IDS),
                "missing tools reported for $name",
            )
        }
    }

    @Test
    fun everyBundledProfileKeepsItsGlobalBlock() {
        PROFILES.forEach { name ->
            assertTrue(bundledText(name).lines().any { it.trim() == "[GLOBAL]" }, "$name.md lost its [GLOBAL] block")
        }
    }

    @Test
    fun theMatcherReportsAGenericToolNamedAsAWholeWord() {
        assertEquals(listOf("synthetic.md: http1_request"), genericToolHits("synthetic.md", "use http1_request now"))
        assertEquals(
            emptyList<String>(),
            genericToolHits("synthetic.md", "xhttp1_request http1_requests http1_request_v2 Http1_request"),
            "only a whole, case-sensitive word matches",
        )
    }

    private fun bundledText(name: String): String {
        val stream = javaClass.classLoader.getResourceAsStream("AGENTS/$name.md")
        assertNotNull(stream, "bundled profile AGENTS/$name.md is missing from the class path")
        return stream!!.use { it.readBytes().toString(Charsets.UTF_8) }
    }

    private fun genericToolHits(
        file: String,
        text: String,
    ): List<String> =
        GENERIC_TOOL_IDS
            .sorted()
            .filter { id -> Regex("(?<![A-Za-z0-9_])${Regex.escape(id)}(?![A-Za-z0-9_])").containsMatchIn(text) }
            .map { "$file: $it" }

    companion object {
        val PROFILES = listOf("pentester", "bughunter", "auditor")

        /** The 8 native tools: the whole tool catalog of the store build. */
        val NATIVE_IDS =
            setOf(
                "status",
                "issue_create",
                "ai_analyze",
                "ai_passive_scan",
                "ai_findings_recent",
                "redact_preview",
                "ai_audit_query",
                "ai_backends_list",
            )

        /** The 51 generic tools of the full build, from the src/full Generic*Tools descriptors. */
        val GENERIC_TOOL_IDS =
            setOf(
                // GenericHistoryTools
                "proxy_http_history",
                "proxy_http_history_regex",
                "proxy_history_annotate",
                "response_body_search",
                "proxy_ws_history",
                "proxy_ws_history_regex",
                // GenericRequestTools
                "http1_request",
                "http2_request",
                "repeater_tab",
                "repeater_tab_with_payload",
                "intruder",
                "intruder_prepare",
                "insertion_points",
                "params_extract",
                "diff_requests",
                "request_parse",
                "response_parse",
                "find_reflected",
                "comparer_send",
                // GenericScannerTools
                "scanner_issues",
                "scan_audit_start",
                "scan_audit_start_mode",
                "scan_audit_start_requests",
                "scan_crawl_start",
                "scan_task_status",
                "scan_task_delete",
                "scan_report",
                "collaborator_generate",
                "collaborator_poll",
                // GenericSiteMapTools
                "site_map",
                "site_map_regex",
                "scope_check",
                "scope_include",
                "scope_exclude",
                // GenericConfigTools
                "project_options_get",
                "user_options_get",
                "project_options_set",
                "user_options_set",
                "task_engine_state",
                "proxy_intercept",
                "editor_get",
                "editor_set",
                // GenericUtilityTools
                "url_encode",
                "url_decode",
                "base64_encode",
                "base64_decode",
                "random_string",
                "hash_compute",
                "jwt_decode",
                "decode_as",
                "cookie_jar_get",
            )

        private val SNAKE_CASE_WORD = Regex("(?<![A-Za-z0-9_])[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?![A-Za-z0-9_])")
    }
}
