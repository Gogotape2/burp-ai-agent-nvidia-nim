package com.six2dez.burp.aiagent.redact

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * WHAT THIS IS FOR.
 *
 * The v0.10.0 milestone audit found one security rule — "is this header a cookie header?" — with two
 * implementations that had drifted apart. Phase 21 widened the prompt path to name-CONTAINS-`cookie`;
 * the MCP tool-result path in `McpToolHelpers.sanitizeHeaders` kept comparing against the two
 * canonical spellings, so `X-Cookie`, `Cookie2`, `Set-Cookie2`, `X-Original-Cookie` and
 * `X-Forwarded-Cookie` reached an AI backend verbatim. Phase 27 promoted the rule to
 * [Redaction.isCookieHeaderName] and routed both header paths plus the passive-scan admitter through
 * it.
 *
 * An execution-time grep can only prove the tree was clean on the day someone ran it. This test makes
 * a FOURTH hand-written implementation fail CI instead, so the invariant outlives the phase that
 * created it.
 *
 * WHAT THIS IS BOUNDED BY — read this before quoting the test as evidence.
 *
 * The scan sees only the five spelling classes enumerated in [MATCHER_SPELLINGS]: exact-name
 * equality, `ignoreCase` equality, a line-prefix test, a Montoya `headerValue` lookup, and a
 * substring test. A cookie matcher spelled OUTSIDE those five classes — a `startsWith` on an
 * already-lowered name, an `in` operator against a set literal, a `when` branch, a name assembled
 * from a constant — is invisible to this scan and leaves this test GREEN.
 *
 * This test is therefore a TRIPWIRE OVER MEASURED SPELLINGS, not a proof of exhaustive coverage.
 * Anyone introducing a new spelling class must add it to [MATCHER_SPELLINGS], or the tripwire
 * silently stops covering their code. A reader who mistakes this tripwire for a proof reproduces,
 * one iteration smaller, the defect the whole phase exists to repair: a record wider than the control
 * it describes.
 *
 * The claim this file supports is scoped accordingly: there is exactly one cookie-header-name rule
 * across the two redaction paths and the passive-scan admitter. Other cookie-header-name matchers
 * survive in `src/main/kotlin` and are classified below as non-redacting, each with the reason read
 * from its own source and consumer.
 */
class CookieHeaderRuleOwnershipTest {
    @Test
    fun noHandWrittenCookieMatcherSurvivesInTheRedactionPaths() {
        REDACTION_PATHS.forEach { path ->
            val hits = matcherHitsIn(SourceRoots.file(path))
            assertTrue(
                hits.isEmpty(),
                "$path is a REDACTION PATH and is not allowlistable: it must call " +
                    "Redaction.isCookieHeaderName rather than write its own cookie-header-name test. " +
                    "redact/Redaction.kt is exempt as the OWNER of the rule; this file is not. " +
                    "Found: $hits",
            )
        }
    }

    @Test
    fun everyCookieHeaderNameMatcherInMainIsClassified() {
        val hitFiles =
            SourceRoots
                .kotlinFiles()
                .filter { matcherHitsIn(it).isNotEmpty() }
                .map(SourceRoots::relativePath)
                .toSet()
        val unaccounted = hitFiles - REDACTION_PATHS - OWNER

        assertEquals(
            CLASSIFIED_NON_REDACTING.keys,
            unaccounted,
            "the set of files with a hand-written cookie-header-name matcher has changed.\n" +
                "  NEW (route it through Redaction.isCookieHeaderName, or classify it in " +
                "CLASSIFIED_NON_REDACTING with the reason you read from its source and its consumer): " +
                "${unaccounted - CLASSIFIED_NON_REDACTING.keys}\n" +
                "  STALE (classified here but no longer matched — remove the entry so the allowlist " +
                "cannot accumulate dead keys): ${CLASSIFIED_NON_REDACTING.keys - unaccounted}",
        )
    }

    @Test
    fun theOwnershipScanIsNonVacuous() {
        // A broken path or an empty walk must FAIL rather than pass silently. A repository-state test
        // that goes green when it cannot find the repository is worse than the grep it replaced.
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the walk found only ${files.size} .kt files under ${SourceRoots.PRODUCTION} — the scan is not " +
                "reaching the repository, so its other assertions prove nothing",
        )

        // And a regex that matches nothing would make the scan vacuously clean. Each spelling class is
        // proven live against a fixture written in that class.
        SPELLING_FIXTURES.forEach { (spelling, fixture) ->
            assertTrue(
                spelling.containsMatchIn(fixture),
                "MATCHER_SPELLINGS entry /${spelling.pattern}/ matched no known positive fixture " +
                    "[$fixture] — it can no longer detect the spelling it exists to detect",
            )
        }
        assertEquals(
            MATCHER_SPELLINGS.size,
            SPELLING_FIXTURES.size,
            "every MATCHER_SPELLINGS entry needs a positive fixture, or an unproven regex can hide " +
                "in the set",
        )
    }

    // ── the scan ─────────────────────────────────────────────────────────────────────────

    private fun matcherHitsIn(file: File): List<String> =
        file
            .readLines()
            .filterNot { isCommentOnly(it) }
            .filter { line -> MATCHER_SPELLINGS.any { it.containsMatchIn(line) } }
            .map { it.trim() }

    // Comment-only lines are stripped so that prose ABOUT a matcher — including this phase's own
    // explanatory comments — cannot be mistaken for a matcher.
    private fun isCommentOnly(line: String): Boolean {
        val trimmed = line.trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private companion object {
        // Measured at 172 .kt files when this test was written. The floor is deliberately well below
        // that: it is here to catch a walk that reaches nothing, not to track the file count.
        const val MIN_EXPECTED_MAIN_FILES = 150

        /**
         * The ways a cookie header name is named BY HAND in this codebase, measured against the tree.
         * Case-sensitive where the Kotlin literal is case-sensitive. THE RULE, stated on its own
         * general ground rather than on one example: a case-insensitive scan would also match
         * comparisons against the uppercase Montoya parameter TYPE name, and a parameter TYPE is not
         * a header NAME — it is a different control, with a different owner
         * ([Redaction.isCookieParameterType]) and a different bound.
         *
         * THE HISTORICAL EXAMPLE, no longer live in the tree: `InjectionPointExtractor.kt` used to
         * write `it.type().name == "COOKIE"` inline, and a case-insensitive scan picked it up. Phase
         * 28 converted that file to the shared parameter-type predicate, so the example is cited here
         * as history rather than as something a reader can go and look at. The rule above does not
         * depend on it — which is the point of restating the rule generally.
         *
         * See the class KDoc for the bound: these five classes are what the scan CAN see.
         */
        val MATCHER_SPELLINGS =
            listOf(
                // exact-name equality, with or without `ignoreCase`
                Regex("equals\\(\"(Set-)?Cookie\""),
                // line-prefix test against a serialised header line
                Regex("startsWith\\(\"(Set-)?Cookie:\""),
                // Montoya header lookup by name
                Regex("headerValue\\(\"(Set-)?Cookie\"\\)"),
                // substring test on a lowered name
                Regex("contains\\(\"cookie\"\\)"),
                // equality against the lowercase canonical spellings
                Regex("== \"(set-)?cookie\""),
            )

        /** One known positive per spelling class, so a regex that matches nothing cannot hide. */
        val SPELLING_FIXTURES =
            MATCHER_SPELLINGS.zip(
                listOf(
                    """.filter { it.name().equals("Cookie", ignoreCase = true) }""",
                    """.filter { it.startsWith("Set-Cookie:", ignoreCase = true) }""",
                    """val cookieHeader = request.headerValue("Cookie") ?: ""}""",
                    """if (name.contains("cookie")) return@filter true""",
                    """if (policy.stripCookies && (lowered == "cookie" || lowered == "set-cookie")) {""",
                ),
            )

        /**
         * The two REDACTION PATHS. Deliberately not allowlistable: the whole phase is about these
         * calling the shared predicate instead of writing their own rule.
         */
        val REDACTION_PATHS =
            setOf(
                "com/six2dez/burp/aiagent/mcp/tools/McpToolHelpers.kt",
                "com/six2dez/burp/aiagent/scanner/PassiveAiScannerFilters.kt",
            )

        /** The OWNER of the rule. A gate that flagged the owner would be flagging the fix. */
        val OWNER = setOf("com/six2dez/burp/aiagent/redact/Redaction.kt")

        /**
         * Every OTHER file the sweep hits, with the source-verified reason it need not route through
         * the predicate. Keyed on path, not line number, so the map does not rot the first time a file
         * is reformatted.
         *
         * Only files the sweep ACTUALLY hits belong here. A key the sweep never hits is a dead entry
         * and fails `everyCookieHeaderNameMatcherInMainIsClassified` in its stale direction — which is
         * why `scanner/PassiveAiScanner.kt` (a bare `"set-cookie"` set member),
         * `scanner/InjectionPointExtractor.kt` (it routes its cookie-TYPE decision through
         * [Redaction.isCookieParameterType] as of phase 28, and contains no cookie-header-NAME matcher
         * in any of the five spellings — its historical form, an uppercase parameter-TYPE compare
         * written inline, was likewise never a header-name matcher, so its zero-hit status is
         * UNCHANGED by that conversion) and `redact/Redaction.kt` (composed from `COOKIE_NAME_TOKEN`)
         * are absent: all three return zero hits.
         *
         * The `InjectionPointExtractor.kt` clause was rewritten by phase 28 even though NOTHING TURNED
         * RED. Its old wording justified the file's absence by describing a construct the conversion
         * removed, so the citation would have rotted while the assertion it justifies stayed green —
         * the harder drift class to notice, precisely because a stale-but-green reason produces no
         * failing test to prompt the fix.
         */
        val CLASSIFIED_NON_REDACTING =
            mapOf(
                "com/six2dez/burp/aiagent/scanner/PassiveAiScannerAnalysis.kt" to
                    "EXTRACTOR. Selects which request Cookie header VALUES feed cookieSectionLines. " +
                    "Fail-safe by DIRECTION: narrowing puts FEWER cookie values into the prompt. Its " +
                    "output reaches a model only via buildScanMetadataText -> redactScanMetadata, " +
                    "which calls Redaction.apply UNCONDITIONALLY, and the COOKIE_SECTION_HEADER span " +
                    "rule redacts the values inside that span.",
                "com/six2dez/burp/aiagent/scanner/PassiveAiScannerHeuristics.kt" to
                    "LOCAL-ANALYSIS. The Set-Cookie filter reduces values to a sameSiteSecure boolean " +
                    "and the Cookie lookup reduces its value to a containsMatchIn boolean; both feed a " +
                    "LocalFinding's severity/suppression decision. No header value crosses the " +
                    "process boundary.",
                "com/six2dez/burp/aiagent/prompts/bountyprompt/BountyPromptTagResolver.kt" to
                    "EXTRACTOR over ALREADY-REDACTED text. extractCookies is called with " +
                    "requestRedacted/responseRedacted, which are the outputs of Redaction.apply, so it " +
                    "filters lines that have already been through the wide prompt-path cookie rules. " +
                    "Narrowing puts fewer already-redacted lines into the tag.",
                "com/six2dez/burp/aiagent/scanner/ActiveAiScanner.kt" to
                    "LOCAL-ANALYSIS and REQUEST MUTATOR. hasAuthContext reduces the Cookie value to a " +
                    "boolean and stripAuthHeaders immediately REMOVES the header; the InjectionType." +
                    "COOKIE branch injects an attack payload into the request sent to the TARGET, not " +
                    "to an AI backend. Neither is a redaction path.",
            )
    }
}
