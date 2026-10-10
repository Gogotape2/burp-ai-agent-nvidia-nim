package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.SourceRoots
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
 * and asserted. A fifteenth site, a site that exists in one executor and not the other, or a fourth
 * tool-registration path all read as a DATA CHANGE here — visible, deliberate, and reviewable —
 * rather than as silence.
 *
 * WHAT MAKES A RULE-LEVEL FIX REACH EVERY SITE. None of the 14 emission sites redacts anything
 * itself. `McpToolLegacy.kt`'s seven all sit inside `mcpPaginatedTool<…>` registrations, which
 * delegate to `mcpTool<I>` (`McpTool.kt:82`), whose handler wraps its output in
 * `context.redactIfNeeded(` (`McpTool.kt:45`). `McpToolExecutorImpl.kt`'s seven all sit inside the
 * dispatch `when` whose result is wrapped at `McpToolExecutorImpl.kt:1037`. That is why changing a
 * regex in `redact/Redaction.kt` reaches all 14 — and it is asserted below from source rather than
 * argued in prose.
 *
 * ── BOUND 1, on the EMISSION-SITE scans (count, per-file split, tool-name presence, choke point) ──
 *
 * They recognise ONE MEASURED CALL SHAPE: `encodeToString(it.toSerializableForm(` /
 * `encodeToString(it.toSiteMapEntry(`. An emission site written in a DIFFERENT SHAPE — a serializer
 * called through a local variable, a hand-built JSON string, a third serializable carrier with a
 * new conversion function — is invisible to every scan in this file and leaves it GREEN.
 *
 * The per-file split, the tool-name presence check and the choke-point assertion are additionally
 * scoped to the TWO NAMED EXECUTOR FILES in [EMISSION_EXECUTOR_FILES]. `theMeasuredEmissionSiteCountIsPinned`
 * does scan all of `src/main/kotlin` for the call shape, so a site added in a THIRD file fails that
 * one assertion — but the shape bound above still holds over the whole tree, and the other three
 * scans still see only two files.
 *
 * ── BOUND 2, on the REGISTRATION-PATH scan, which is a DIFFERENT AND WEAKER BOUND ──
 *
 * `everyToolRegistrationPathReachesTheChokePoint` covers ALL of `src/main/kotlin` for one call name,
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
        val perFile = EMISSION_EXECUTOR_FILES.associateWith { emissionSitesIn(it).size }

        perFile.forEach { (path, count) ->
            assertEquals(
                EXPECTED_SITES_PER_EXECUTOR,
                count,
                "$path carries $count serialized-emission sites, not $EXPECTED_SITES_PER_EXECUTOR. " +
                    "If that is deliberate, update EXPECTED_SITES_PER_EXECUTOR and the tool-name sets " +
                    "together and re-measure the whole inventory — do not adjust one number in " +
                    "isolation. Sites found: ${emissionSitesIn(path)}",
            )
        }
        assertEquals(
            EXPECTED_EMISSION_SITES,
            perFile.values.sum(),
            "the measured serialized-emission inventory has drifted from the pinned total. Per file: $perFile",
        )

        // The split is asserted against the tool-name sets rather than restated as a second literal,
        // so the counts and the names cannot disagree with each other.
        assertEquals(
            EXPECTED_RAW_HTTP_EMISSION_SITES,
            RAW_HTTP_EMISSION_TOOL_NAMES.size * EMISSION_EXECUTOR_FILES.size,
            "the raw-HTTP site count and the raw-HTTP tool-name set disagree: " +
                "${RAW_HTTP_EMISSION_TOOL_NAMES.size} names across ${EMISSION_EXECUTOR_FILES.size} executors",
        )
        assertEquals(
            EXPECTED_WEBSOCKET_EMISSION_SITES,
            WEBSOCKET_EMISSION_TOOL_NAMES.size * EMISSION_EXECUTOR_FILES.size,
            "the WebSocket site count and the WebSocket tool-name set disagree: " +
                "${WEBSOCKET_EMISSION_TOOL_NAMES.size} names across ${EMISSION_EXECUTOR_FILES.size} executors",
        )
        assertEquals(
            EXPECTED_EMISSION_SITES,
            EXPECTED_RAW_HTTP_EMISSION_SITES + EXPECTED_WEBSOCKET_EMISSION_SITES,
            "the two carrier splits must account for the whole inventory, or a site belongs to neither",
        )

        // The one place the emission scan is NOT limited to the two named executors. A third file
        // that adopted this call shape is the "eleventh site" failure mode in its purest form, and
        // it costs three lines to make it fail here instead of being discovered by an audit.
        val strays =
            SourceRoots
                .kotlinFiles()
                .map(SourceRoots::relativePath)
                .filterNot { it in EMISSION_EXECUTOR_FILES }
                .filter { emissionSitesIn(it).isNotEmpty() }
        assertTrue(
            strays.isEmpty(),
            "the measured serialized-emission call shape appears OUTSIDE the two pinned executor " +
                "files, so this inventory no longer describes the tree: $strays. Add the file to " +
                "EMISSION_EXECUTOR_FILES and re-measure every constant here, or route the new site " +
                "through an existing executor.",
        )
    }

    @Test
    fun everyEmissionToolNameAppearsInBothExecutors() {
        val allNames = RAW_HTTP_EMISSION_TOOL_NAMES + WEBSOCKET_EMISSION_TOOL_NAMES

        EMISSION_EXECUTOR_FILES.forEach { path ->
            val code = codeLines(path)
            allNames.forEach { name ->
                assertTrue(
                    code.any { it.text.contains("\"$name\"") },
                    "the tool name \"$name\" is not registered in $path. Every emitting tool exists " +
                        "in BOTH executors — the modern dispatcher and the legacy registrar — and a " +
                        "name present in one and absent from the other is a site whose privacy " +
                        "behaviour was only ever checked on one path. That asymmetry is the defect " +
                        "class this phase exists to close.",
                )
            }
        }
    }

    @Test
    fun everyEmissionSiteIsDownstreamOfTheSingleRedactingChokePoint() {
        // WHY THIS MATTERS: it is the structural reason a one-line change to a regex in
        // redact/Redaction.kt reaches all 14 emission sites. Without it, "we fixed the rule" would
        // be a claim about one call site and a hope about thirteen others.

        // ── the legacy registrar: every emission site sits inside an mcpPaginatedTool registration,
        //    which delegates to mcpTool<I>, whose handler wraps in context.redactIfNeeded(.
        val legacyRegistrations = codeLines(LEGACY_EXECUTOR).filter { REGISTRATION_CALL.containsMatchIn(it.text) }
        assertTrue(legacyRegistrations.isNotEmpty(), "no mcpTool/mcpPaginatedTool registration found in $LEGACY_EXECUTOR")

        emissionSitesIn(LEGACY_EXECUTOR).forEach { site ->
            val enclosing =
                legacyRegistrations.lastOrNull { it.number < site.number }
                    ?: throw AssertionError(
                        "the emission site at $LEGACY_EXECUTOR:${site.number} has no mcpTool/mcpPaginatedTool " +
                            "registration in front of it, so nothing in this file places it behind " +
                            "context.redactIfNeeded(",
                    )
            assertTrue(
                enclosing.text.contains("mcpPaginatedTool<"),
                "$LEGACY_EXECUTOR:${site.number} is registered by ${enclosing.text.trim()} " +
                    "(line ${enclosing.number}) rather than by mcpPaginatedTool<…>. Both registrars route " +
                    "through mcpTool<I> and its context.redactIfNeeded( wrapper, so this is a drift " +
                    "signal rather than a leak — but it means the inventory's shape claim is stale, " +
                    "so re-measure before relaxing it.",
            )
        }
        assertEquals(
            0,
            codeLines(LEGACY_EXECUTOR).count { it.text.contains("redactIfNeeded") },
            "$LEGACY_EXECUTOR redacts nothing itself. If that changes, the claim that its sites are " +
                "safe BY REGISTRATION rather than by local wrapping needs re-stating.",
        )

        // ── the modern dispatcher: every emission site sits inside the dispatch `when` whose result
        //    is wrapped at the single choke point below.
        val executorSites = emissionSitesIn(MODERN_EXECUTOR)
        val chokePoints = codeLines(MODERN_EXECUTOR).filter { it.text.contains(EXECUTOR_CHOKE_POINT) }
        assertEquals(
            1,
            chokePoints.size,
            "$MODERN_EXECUTOR must carry exactly ONE `$EXECUTOR_CHOKE_POINT` line — the single point " +
                "every dispatched tool's output passes through. Found: $chokePoints",
        )
        // POSITIONAL PROXY, stated rather than hidden: the wrapper being the LAST thing in the
        // function, after every branch that produces a payload, is what a line scan can see of
        // "the whole `when` result flows through it". A restructure that moved a branch after the
        // wrapper is what this catches; a branch that returned early past it is not.
        assertTrue(
            chokePoints.single().number > executorSites.maxOf { it.number },
            "$MODERN_EXECUTOR's `$EXECUTOR_CHOKE_POINT` is at line ${chokePoints.single().number}, " +
                "BEFORE its last emission site at line ${executorSites.maxOf { it.number }}. An " +
                "emission branch that runs after the wrapper is not redacted by it.",
        )
    }

    @Test
    fun everyToolRegistrationPathReachesTheChokePoint() {
        // The THIRD registration path is the one the criterion above cannot see, and it is the one a
        // reader of the choke-point claim would otherwise never meet.
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

        // Path A and B — McpTool.kt's two addTool calls each wrap their own handler output.
        val wrapperRegions = regionsAfter(WRAPPER_REGISTRAR, ADD_TOOL_CALL)
        assertEquals(
            EXPECTED_ADD_TOOL_SITES.getValue(WRAPPER_REGISTRAR),
            wrapperRegions.size,
            "expected ${EXPECTED_ADD_TOOL_SITES.getValue(WRAPPER_REGISTRAR)} addTool regions in $WRAPPER_REGISTRAR",
        )
        wrapperRegions.forEach { (startLine, region) ->
            assertTrue(
                region.any { it.text.contains(HANDLER_WRAPPER) },
                "$WRAPPER_REGISTRAR:$startLine registers a tool whose handler does NOT wrap its output " +
                    "in `$HANDLER_WRAPPER`. This is THE choke point: mcpTool, its Unit overload and " +
                    "mcpPaginatedTool all funnel through these two handlers, so an unwrapped one " +
                    "un-redacts every tool registered through it.",
            )
        }

        // Path C — McpToolHandlers.kt:registerToolHandler. It carries NO wrapper of its own and is
        // safe ONLY because its handler delegates to McpToolExecutor.executeToolResult, which reaches
        // context.redactIfNeeded(output) inside McpToolExecutorImpl. Asserted explicitly rather than
        // left unnamed: a version of the choke-point claim that mentions only mcpTool and
        // mcpPaginatedTool leaves this path unmeasured, which is the same shape of omission as the
        // partial emission-site inventory this file exists to replace.
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
            val hits = EMISSION_EXECUTOR_FILES.sumOf { path -> emissionSitesIn(path).count { it.text.contains(function) } }
            assertTrue(
                hits >= 1,
                "the emission scan found no `$function` call in either executor — the regex " +
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
            emissionSitesIn(LEGACY_EXECUTOR).none { isCommentOnly(it.text) },
            "a comment-only line reached the emission inventory",
        )
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

    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private companion object {
        const val TOOLS_PACKAGE = "com/six2dez/burp/aiagent/mcp/tools"

        /** Measured at 172 .kt files. The floor catches a walk that reaches nothing, not drift. */
        const val MIN_EXPECTED_MAIN_FILES = 150

        // ── the two executors that carry every measured emission site ─────────────────────
        const val MODERN_EXECUTOR = "$TOOLS_PACKAGE/McpToolExecutorImpl.kt"
        const val LEGACY_EXECUTOR = "$TOOLS_PACKAGE/McpToolLegacy.kt"
        val EMISSION_EXECUTOR_FILES = listOf(MODERN_EXECUTOR, LEGACY_EXECUTOR)

        // ── the measured inventory ────────────────────────────────────────────────────────
        //
        // grep -rhE "encodeToString\(it\.(toSerializableForm|toSiteMapEntry)\(" \
        //   src/main/kotlin/com/six2dez/burp/aiagent/mcp/tools/ --include=*.kt | wc -l  ->  14
        //
        // McpToolExecutorImpl.kt  608 740 760 836 855 873 896   (7)
        // McpToolLegacy.kt        475 622 639 713 729 744 764   (7)
        //
        // Seven tool names, each registered once per executor. Five carry a raw HTTP message; two
        // carry a WebSocket payload, which has no header block and therefore no header rule to miss.
        const val EXPECTED_EMISSION_SITES = 14
        const val EXPECTED_SITES_PER_EXECUTOR = 7
        const val EXPECTED_RAW_HTTP_EMISSION_SITES = 10
        const val EXPECTED_WEBSOCKET_EMISSION_SITES = 4

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

        /** The legacy registrars, either of which routes through mcpTool<I>'s wrapping handler. */
        val REGISTRATION_CALL = Regex("""\bmcp(?:Paginated)?Tool\s*[<(]""")

        // ── the three registration paths, measured ────────────────────────────────────────
        //
        // grep -rn 'addTool(' src/main/kotlin --include=*.kt  ->  McpTool.kt:34, McpTool.kt:72,
        // McpToolHandlers.kt:122. Pinned by path and count rather than by line number, so an
        // unrelated edit above line 34 does not rot the gate; the line numbers are recorded in the
        // plan's SUMMARY where they cost nothing to keep accurate.
        const val ADD_TOOL_CALL = "addTool("
        const val WRAPPER_REGISTRAR = "$TOOLS_PACKAGE/McpTool.kt"
        const val DELEGATING_REGISTRAR = "$TOOLS_PACKAGE/McpToolHandlers.kt"
        val EXPECTED_ADD_TOOL_SITES = mapOf(WRAPPER_REGISTRAR to 2, DELEGATING_REGISTRAR to 1)

        const val HANDLER_WRAPPER = "context.redactIfNeeded("
        const val EXECUTOR_CHOKE_POINT = "context.redactIfNeeded(output)"
        const val EXECUTOR_DELEGATION = "McpToolExecutor.executeToolResult("

        /** Floors, not counts. Measured: 1363 / 840 / 242 / 174. */
        val MIN_EXPECTED_LINES =
            mapOf(
                MODERN_EXECUTOR to 1000,
                LEGACY_EXECUTOR to 600,
                WRAPPER_REGISTRAR to 150,
                DELEGATING_REGISTRAR to 100,
            )
    }
}
