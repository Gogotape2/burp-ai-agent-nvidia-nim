package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * (PRIV-05) Phase 27 plan 27-05 / D-27-14 — the emission-site inventory, pinned by measurement.
 *
 * WHAT THIS IS FOR.
 *
 * Phase 27 exists because a privacy control was verified at the one site it was written for and
 * never compared against its siblings. The set of MCP tool-result sites that serialize a raw HTTP
 * message into a JSON string was never enumerated: the phase verifier cited 12 such sites, the UAT
 * note cited 10, and both were partial. A number nobody measured is a number nobody can defend, and
 * "did we get them all?" stayed a review question when it should have been a test result.
 *
 * This file converts it into a test result. The inventory is measured, declared as named constants,
 * and asserted. An eighth site, a site outside the executor, or a second tool-registration path all
 * read as a DATA CHANGE here — visible, deliberate, and reviewable — rather than as silence.
 *
 * WHAT MAKES A RULE-LEVEL FIX REACH EVERY SITE. None of the 7 emission sites redacts anything
 * itself. Since plan 29-08 every one of them sits inside a tool HANDLER BODY — a `toolHandler(`
 * lambda in a handler file (plan 29-06 started the conversion; 29-08 deleted the executor's residual
 * dispatch `when` the last 23 tools delegated to) — and `McpToolExecutor.executeToolResult`
 * wraps every `handler.execute(...)` result at its single `context.redactIfNeeded(handler.execute(` line. That is why changing a regex in
 * `redact/Redaction.kt` reaches all 7 — and it is asserted below from source rather than argued in
 * prose.
 *
 * Phase 29 plan 29-04 (DEAD-01) deleted the legacy MCP registrar, which carried a second copy of
 * the same seven sites behind its own wrapping registration helpers in `McpTool.kt`. Its rows were
 * removed from this inventory and the helpers went with it; the whole-tree scans below still walk
 * both production roots, so a site that reappears anywhere fails here.
 *
 * ── BOUND 1, on the EMISSION-SITE scans (count, per-file split, tool-name presence, choke point) ──
 *
 * They recognise ONE MEASURED CALL SHAPE: `encodeToString(it.toSerializableForm(` /
 * `encodeToString(it.toSiteMapEntry(`. An emission site written in a DIFFERENT SHAPE — a serializer
 * called through a local variable, a hand-built JSON string, a third serializable carrier with a
 * new conversion function — is invisible to every scan in this file and leaves it GREEN.
 *
 * The per-file count, the tool-name presence check and the handler-body attribution are additionally
 * scoped to the NAMED FILES in [EMISSION_SITE_FILES]. `theMeasuredEmissionSiteCountIsPinned` does scan
 * every production root for the call shape, so a site added in ANOTHER file fails that one assertion —
 * but the shape bound above still holds over the whole tree, and the other scans still see only the
 * named files. The handler-body attribution is a LINE-REGION proxy (a site after a `toolHandler(` call),
 * not a parse of Kotlin.
 *
 * ── BOUND 2, on the REGISTRATION-PATH scan, which is a DIFFERENT AND WEAKER BOUND ──
 *
 * `everyToolRegistrationPathReachesTheChokePoint` covers every production root for one call name,
 * `addTool(`. But it proves choke-point reachability only for the DELEGATION SHAPE AS WRITTEN: it
 * asserts that `McpToolHandlers.registerToolHandler`'s handler calls
 * `McpToolExecutor.executeToolResult(` and carries no wrapper of its own. A future handler that KEPT
 * that call and ALSO serialized and emitted its own payload beside it would still pass. A tool
 * registered through some mechanism other than `addTool(` is invisible to it entirely.
 *
 * ── WHAT THIS FILE IS, THEREFORE ──
 *
 * A TRIPWIRE OVER A MEASURED INVENTORY, not a proof of coverage. Nothing here says every path that
 * can reach an AI backend is redacted. A reader who quotes it as such reproduces, one iteration
 * smaller, the defect this phase exists to repair: a record wider than the control it describes.
 * `CookieHeaderRuleOwnershipTest` states its own five-spelling bound in the same place and for the
 * same reason.
 */
class SerializedEmissionSiteInventoryTest {
    @Test
    fun theMeasuredEmissionSiteCountIsPinned() {
        val perFile = EMISSION_SITE_FILES.keys.associateWith { emissionSitesIn(it).size }

        assertEquals(
            EMISSION_SITE_FILES,
            perFile,
            "the per-file serialized-emission inventory has drifted. If that is deliberate, update " +
                "EMISSION_SITE_FILES and the tool-name sets together and re-measure the whole inventory " +
                "— do not adjust one number in isolation. Sites found: " +
                EMISSION_SITE_FILES.keys.associateWith { emissionSitesIn(it) },
        )
        assertEquals(
            EXPECTED_EMISSION_SITES,
            perFile.values.sum(),
            "the measured serialized-emission inventory has drifted from the pinned total. Per file: $perFile",
        )

        // The split is asserted against the tool-name sets rather than restated as a second literal,
        // so the counts and the names cannot disagree with each other. Each tool emits at ONE site.
        assertEquals(
            EXPECTED_RAW_HTTP_EMISSION_SITES,
            RAW_HTTP_EMISSION_TOOL_NAMES.size,
            "the raw-HTTP site count and the raw-HTTP tool-name set disagree",
        )
        assertEquals(
            EXPECTED_WEBSOCKET_EMISSION_SITES,
            WEBSOCKET_EMISSION_TOOL_NAMES.size,
            "the WebSocket site count and the WebSocket tool-name set disagree",
        )
        assertEquals(
            EXPECTED_EMISSION_SITES,
            EXPECTED_RAW_HTTP_EMISSION_SITES + EXPECTED_WEBSOCKET_EMISSION_SITES,
            "the two carrier splits must account for the whole inventory, or a site belongs to neither",
        )

        // The one place the emission scan is NOT limited to the named files. Another file that adopted
        // this call shape is the "eleventh site" failure mode in its purest form, and it costs three
        // lines to make it fail here instead of being discovered by an audit.
        val strays =
            SourceRoots
                .kotlinFiles()
                .map(SourceRoots::relativePath)
                .filterNot { it in EMISSION_SITE_FILES.keys }
                .filter { emissionSitesIn(it).isNotEmpty() }
        assertTrue(
            strays.isEmpty(),
            "the measured serialized-emission call shape appears OUTSIDE the pinned files, so this " +
                "inventory no longer describes the tree: $strays. Add the file to EMISSION_SITE_FILES " +
                "and re-measure every constant here.",
        )
    }

    @Test
    fun everyEmissionToolNameIsDeclaredInAPinnedFile() {
        val allNames = RAW_HTTP_EMISSION_TOOL_NAMES + WEBSOCKET_EMISSION_TOOL_NAMES
        val code = EMISSION_SITE_FILES.keys.flatMap { codeLines(it) }
        allNames.forEach { name ->
            assertTrue(
                code.any { it.text.contains("\"$name\"") },
                "the tool name \"$name\" is not declared in any of ${EMISSION_SITE_FILES.keys}. Every " +
                    "emitting tool in the pinned inventory is a handler in one of them; a name that " +
                    "disappeared means the counts above describe a tool set that no longer exists, so " +
                    "re-measure the whole inventory rather than one number.",
            )
        }
    }

    @Test
    fun everyEmissionSiteIsDownstreamOfTheSingleRedactingChokePoint() {
        // WHY THIS MATTERS: it is the structural reason a one-line change to a regex in
        // redact/Redaction.kt reaches all 7 emission sites. Without it, "we fixed the rule" would
        // be a claim about one call site and a hope about six others.

        // 1. The executor wraps every handler's result, exactly once, inside executeToolResult.
        val chokePoints = codeLines(MODERN_EXECUTOR).filter { it.text.contains(EXECUTOR_CHOKE_POINT) }
        assertEquals(
            1,
            chokePoints.size,
            "$MODERN_EXECUTOR must carry exactly ONE `$EXECUTOR_CHOKE_POINT` line — the single point " +
                "every dispatched handler's output passes through. Found: $chokePoints",
        )
        val executeToolResult = memberFunctionRegion(MODERN_EXECUTOR, "fun executeToolResult(")
        assertTrue(
            chokePoints.single().number in executeToolResult,
            "$MODERN_EXECUTOR's `$EXECUTOR_CHOKE_POINT` (line ${chokePoints.single().number}) is not inside " +
                "executeToolResult ($executeToolResult), the one door every MCP and chat tool call passes.",
        )

        // 2. Every emission site is inside a handler body, so it is what handler.execute returns.
        EMISSION_SITE_FILES.keys.forEach { path ->
            val bodies = regionsAfter(path, HANDLER_FACTORY).map { (start, region) -> start..region.last().number }
            emissionSitesIn(path).forEach { site ->
                assertTrue(
                    bodies.any { site.number in it },
                    "$path:${site.number} is a serialized-emission site outside every tool handler body " +
                        "($bodies). Only a handler's result passes the choke point; a site anywhere else " +
                        "is not redacted by it: $site",
                )
            }
        }

        // 3. Plan 29-08 deleted the executor's residual dispatch `when`: the executor is a dispatcher
        //    and names no tool. A tool-id literal coming back into it is a tool body beside the
        //    registry — a second path this inventory's handler-body attribution does not cover.
        val executorCode = codeLines(MODERN_EXECUTOR)
        val toolIdsInExecutor =
            McpToolCatalog
                .all()
                .map { it.id }
                .filter { id -> executorCode.any { it.text.contains("\"$id\"") } }
        assertTrue(
            toolIdsInExecutor.isEmpty(),
            "$MODERN_EXECUTOR names the tool id(s) $toolIdsInExecutor. Every tool body is a handler next " +
                "to its descriptor (D-13); the executor dispatches through the registry and carries no " +
                "tool-specific code.",
        )
    }

    @Test
    fun everyToolRegistrationPathReachesTheChokePoint() {
        // The registration path is the one the criterion above cannot see, and it is the one a
        // reader of the choke-point claim would otherwise never meet. Since plan 29-04 deleted the
        // wrapping registration helpers in McpTool.kt it is also the ONLY `addTool(` site.
        val hitsByFile =
            SourceRoots
                .kotlinFiles()
                .associate { SourceRoots.relativePath(it) to codeLines(SourceRoots.relativePath(it)).count { line -> line.text.contains(ADD_TOOL_CALL) } }
                .filterValues { it > 0 }

        assertEquals(
            EXPECTED_ADD_TOOL_SITES,
            hitsByFile,
            "the set of `$ADD_TOOL_CALL` registration sites has changed. Every one of them must place " +
                "its handler's output behind McpToolContext.redactIfNeeded, either by wrapping it " +
                "directly or by delegating to McpToolExecutor.executeToolResult. A new site that does " +
                "neither emits un-redacted tool output to the configured AI backend.\n" +
                "  Keyed on PATH and COUNT, not on line number, so the pin does not rot the first " +
                "time a file above one of these lines is reformatted (same discipline as " +
                "CookieHeaderRuleOwnershipTest's path-keyed allowlist).",
        )

        // McpToolHandlers.kt:registerToolHandler. It carries NO wrapper of its own and is safe ONLY
        // because its handler delegates to McpToolExecutor.executeToolResult, which reaches
        // context.redactIfNeeded(output) inside McpToolExecutorImpl. Asserted explicitly rather than
        // left unnamed, because the delegation IS its only control.
        val delegatingRegions = regionsAfter(DELEGATING_REGISTRAR, ADD_TOOL_CALL)
        assertEquals(
            EXPECTED_ADD_TOOL_SITES.getValue(DELEGATING_REGISTRAR),
            delegatingRegions.size,
            "expected ${EXPECTED_ADD_TOOL_SITES.getValue(DELEGATING_REGISTRAR)} addTool region in $DELEGATING_REGISTRAR",
        )
        delegatingRegions.forEach { (startLine, region) ->
            assertTrue(
                region.any { it.text.contains(EXECUTOR_DELEGATION) },
                "$DELEGATING_REGISTRAR:$startLine registers a tool whose handler neither wraps in " +
                    "`$HANDLER_WRAPPER` nor delegates to `$EXECUTOR_DELEGATION`. It therefore emits " +
                    "whatever it built, un-redacted. This handler has no wrapper of its own by design; " +
                    "the delegation IS its only control.",
            )
        }
        assertEquals(
            0,
            codeLines(DELEGATING_REGISTRAR).count { it.text.contains("redactIfNeeded") },
            "$DELEGATING_REGISTRAR is documented here — in this test and in the class KDoc — as safe " +
                "ONLY BY DELEGATION. If it now redacts something directly, that record is stale and " +
                "the reachability claim has to be re-derived rather than re-worded.",
        )
    }

    @Test
    fun theInventoryScanIsNonVacuous() {
        // Resolving the roots is itself the first assertion: SourceRoots.kotlinFiles() throws
        // AssertionError on a missing or empty root, so a scan that cannot find the repository FAILS. A
        // repository-state test that goes green when it cannot see the repository is worse than the
        // grep it replaced.
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the walk found only ${files.size} .kt files under ${SourceRoots.PRODUCTION} — the scan is not " +
                "reaching the repository, so its other assertions prove nothing",
        )

        // Source-line floors. A file emptied, moved or renamed would otherwise produce zero hits and
        // read as agreement with a zero inventory.
        MIN_EXPECTED_LINES.forEach { (path, floor) ->
            val lines = SourceRoots.file(path).readLines().size
            assertTrue(
                lines >= floor,
                "$path has $lines lines, below the floor of $floor — the scan is looking at the wrong " +
                    "file, or the file it pins has been gutted",
            )
        }

        // Each scanned symbol proven live against a real positive, so an inventory of zero cannot
        // pass as agreement with a pinned count of zero.
        EMISSION_FUNCTIONS.forEach { function ->
            val hits = EMISSION_SITE_FILES.keys.sumOf { path -> emissionSitesIn(path).count { it.text.contains(function) } }
            assertTrue(
                hits >= 1,
                "the emission scan found no `$function` call in the pinned files — the regex " +
                    "/${EMISSION_CALL.pattern}/ can no longer detect the shape it exists to detect",
            )
        }
        assertTrue(
            EMISSION_CALL.containsMatchIn(EMISSION_FIXTURE),
            "the emission regex /${EMISSION_CALL.pattern}/ no longer matches its own known positive " +
                "fixture [$EMISSION_FIXTURE]",
        )
        assertTrue(
            SourceRoots.kotlinFiles().sumOf { f -> codeLines(SourceRoots.relativePath(f)).count { it.text.contains(ADD_TOOL_CALL) } } >= 1,
            "the registration scan found no `$ADD_TOOL_CALL` call anywhere in ${SourceRoots.PRODUCTION}",
        )

        // And comment stripping is proven live. This file's own KDoc names every symbol the scans
        // look for; an unfiltered scan would count that prose as evidence.
        assertTrue(isCommentOnly("    // $EMISSION_FIXTURE"), "the comment filter no longer recognises a line comment")
        assertTrue(isCommentOnly("     * $EMISSION_FIXTURE"), "the comment filter no longer recognises a KDoc body line")
        assertTrue(
            EMISSION_SITE_FILES.keys.flatMap { emissionSitesIn(it) }.none { isCommentOnly(it.text) },
            "a comment-only line reached the emission inventory",
        )
        // And the region scans are proven to find what they look for.
        assertTrue(regionsAfter(GENERIC_SCANNER, HANDLER_FACTORY).isNotEmpty(), "the scanner handler regions are empty")
        assertTrue(memberFunctionRegion(MODERN_EXECUTOR, "fun executeToolResult(").count() > 1, "the executeToolResult region is empty")
    }

    // ── the scans ─────────────────────────────────────────────────────────────────────────

    private data class SourceLine(
        val number: Int,
        val text: String,
    ) {
        override fun toString(): String = "$number:${text.trim()}"
    }

    /** Non-comment lines of [relPath], 1-based, so prose about a symbol never counts as the symbol. */
    private fun codeLines(relPath: String): List<SourceLine> =
        SourceRoots
            .file(relPath)
            .readLines()
            .mapIndexed { index, text -> SourceLine(index + 1, text) }
            .filterNot { isCommentOnly(it.text) }

    private fun emissionSitesIn(relPath: String): List<SourceLine> = codeLines(relPath).filter { EMISSION_CALL.containsMatchIn(it.text) }

    /**
     * Splits [relPath] into one region per [marker] occurrence, each running from that occurrence to
     * the next one (or to end of file). Used to attribute a handler body to the `addTool(` call that
     * registers it without parsing Kotlin.
     */
    private fun regionsAfter(
        relPath: String,
        marker: String,
    ): List<Pair<Int, List<SourceLine>>> {
        val code = codeLines(relPath)
        val starts = code.withIndex().filter { it.value.text.contains(marker) }
        return starts.mapIndexed { position, (index, line) ->
            val end = starts.getOrNull(position + 1)?.index ?: code.size
            line.number to code.subList(index, end)
        }
    }

    /**
     * The 1-based line range of the `McpToolExecutor` member whose declaration contains [declaration]:
     * from that line to the first line that is exactly the member's closing brace (four-space indent).
     */
    private fun memberFunctionRegion(
        relPath: String,
        declaration: String,
    ): IntRange {
        val lines = SourceRoots.file(relPath).readLines()
        val start = lines.indexOfFirst { it.contains(declaration) }
        assertTrue(start >= 0, "$relPath no longer declares `$declaration`")
        val end = (start + 1 until lines.size).first { lines[it] == "    }" }
        return (start + 1)..(end + 1)
    }

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private companion object {
        const val TOOLS_PACKAGE = "com/six2dez/burp/aiagent/mcp/tools"

        /** Measured at 172 .kt files (185 at plan 29-04). The floor catches a walk that reaches nothing, not drift. */
        const val MIN_EXPECTED_MAIN_FILES = 150

        // ── the files that carry every measured emission site, with their measured counts ────
        const val MODERN_EXECUTOR = "$TOOLS_PACKAGE/McpToolExecutorImpl.kt"
        const val GENERIC_SCANNER = "$TOOLS_PACKAGE/GenericScannerTools.kt"
        const val GENERIC_HISTORY = "$TOOLS_PACKAGE/GenericHistoryTools.kt"
        const val GENERIC_SITE_MAP = "$TOOLS_PACKAGE/GenericSiteMapTools.kt"

        // ── the measured inventory ────────────────────────────────────────────────────────
        //
        // grep -rhE "encodeToString\(it\.(toSerializableForm|toSiteMapEntry)\(" \
        //   src/main/kotlin src/full/kotlin --include=*.kt | wc -l  ->  7   (plan 29-08, task 1)
        //
        // GenericHistoryTools.kt  4  proxy_http_history, proxy_http_history_regex, proxy_ws_history,
        //                            proxy_ws_history_regex — one per toolHandler body
        // GenericSiteMapTools.kt  2  site_map, site_map_regex — one per toolHandler body
        // GenericScannerTools.kt  1  scanner_issues — its toolHandler body (plan 29-08 moved it out of
        //                            the executor's residual dispatch, which is gone)
        //
        // Seven tool names, each dispatched once. Five carry a raw HTTP message; two carry a
        // WebSocket payload, which has no header block and therefore no header rule to miss.
        val EMISSION_SITE_FILES: Map<String, Int> =
            mapOf(
                GENERIC_HISTORY to 4,
                GENERIC_SITE_MAP to 2,
                GENERIC_SCANNER to 1,
            )
        const val EXPECTED_EMISSION_SITES = 7
        const val EXPECTED_RAW_HTTP_EMISSION_SITES = 5
        const val EXPECTED_WEBSOCKET_EMISSION_SITES = 2

        val RAW_HTTP_EMISSION_TOOL_NAMES =
            setOf(
                "scanner_issues",
                "proxy_http_history",
                "proxy_http_history_regex",
                "site_map",
                "site_map_regex",
            )
        val WEBSOCKET_EMISSION_TOOL_NAMES =
            setOf(
                "proxy_ws_history",
                "proxy_ws_history_regex",
            )

        /** The ONE measured call shape. See BOUND 1 in the class KDoc for what it cannot see. */
        val EMISSION_CALL = Regex("""encodeToString\(it\.(?:toSerializableForm|toSiteMapEntry)\(""")
        val EMISSION_FUNCTIONS = listOf("toSerializableForm", "toSiteMapEntry")
        const val EMISSION_FIXTURE = ".map { toolJson.encodeToString(it.toSerializableForm(preprocess)) },"

        // ── the registration path, measured ───────────────────────────────────────────────
        //
        // grep -rn 'addTool(' src/main/kotlin src/full/kotlin --include=*.kt  ->
        // McpToolHandlers.kt:122 (plan 29-04; the two McpTool.kt sites were deleted with the
        // legacy registrar's helpers). Pinned by path and count rather than by line number, so an
        // unrelated edit above the call does not rot the gate.
        const val ADD_TOOL_CALL = "addTool("
        const val DELEGATING_REGISTRAR = "$TOOLS_PACKAGE/McpToolHandlers.kt"
        val EXPECTED_ADD_TOOL_SITES = mapOf(DELEGATING_REGISTRAR to 1)

        const val HANDLER_WRAPPER = "context.redactIfNeeded("
        const val EXECUTOR_CHOKE_POINT = "context.redactIfNeeded(handler.execute("
        const val EXECUTOR_DELEGATION = "McpToolExecutor.executeToolResult("

        // ── handler bodies ──────────────────────────────────────────────────────────────────
        const val HANDLER_FACTORY = "toolHandler("

        /** Floors, not counts. Measured at plan 29-08 task 1: 338 / 71 / 281 / 156 / 375. */
        val MIN_EXPECTED_LINES =
            mapOf(
                MODERN_EXECUTOR to 250,
                DELEGATING_REGISTRAR to 50,
                GENERIC_HISTORY to 200,
                GENERIC_SITE_MAP to 100,
                GENERIC_SCANNER to 250,
            )
    }
}
