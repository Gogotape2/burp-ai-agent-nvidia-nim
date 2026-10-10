package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.params.ParsedHttpParameter
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.mockito.stubbing.Answer
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * WHAT THIS IS FOR.
 *
 * Phase 27 (D-27-17) deliberately REFUSED to convert `InjectionPointExtractor.kt`'s hand-written
 * `it.type().name == "COOKIE"` filter to the shared [com.six2dez.burp.aiagent.redact.Redaction]
 * predicate, and wrote the reason into `Redaction.isCookieParameterType`'s KDoc: while the
 * issue-detail route the extractor feeds was still uncontrolled, swapping the predicate would have
 * produced a tidier file and an unchanged leak — a route that merely LOOKED addressed.
 *
 * Plan 28-01 controlled that route at its write site
 * ([ScannerIssueSupport.sanitizeInjectionPointValue]). Plan 28-02 then collected the conversion.
 * That commit falsifies the predicate COUNT the KDoc pinned, so this file re-derives the count from
 * the tree instead of letting a new number be restated in prose where it would go stale silently.
 *
 * WHAT THIS IS BOUNDED BY — read this before quoting the test as evidence.
 *
 * The scan sees only the four spelling classes enumerated in [COOKIE_TYPE_COMPARISONS]: literal
 * equality/inequality in either operand order, an `equals("COOKIE"` call, and equality against the
 * owner's `COOKIE_PARAMETER_TYPE_NAME` constant. Two constructs are OUTSIDE that population BY
 * DESIGN, and naming them here is what keeps the count honest:
 *
 * 1. `InjectionPointExtractor.matchInsertionPoint`'s `when (param.type().name)` maps all THREE
 *    Montoya type names (`URL`, `BODY`, `COOKIE`) to [InjectionType] values. That is a three-way
 *    dispatch, not a cookie predicate. Converting only its COOKIE arm would leave a `when` whose
 *    arms are spelled two different ways — less readable than either consistent form — so plan
 *    28-02 left it, and a bare `"COOKIE" ->` arm is therefore not counted here.
 * 2. `Redaction.COOKIE_PARAMETER_TYPE_NAME`'s own `= "COOKIE"` declaration is a DECLARATION, not a
 *    comparison. Counting the owner's constant would make the owner look like a duplicate of itself.
 * 3. `scanner/AiScanCheck.kt`'s `insertionPoint.type() == AuditInsertionPointType.PARAM_COOKIE`
 *    (plan 28-05, route 2 of `AR-27-08`) is a DIFFERENT POPULATION, and the reason is measured
 *    rather than asserted. Every spelling in [COOKIE_TYPE_COMPARISONS] compares a Montoya
 *    **parameter**-type NAME against the literal `COOKIE`. `AuditInsertionPointType` is a different
 *    closed enum, its cookie member is named `PARAM_COOKIE`, and no comparison against the literal
 *    `COOKIE` can ever be true of it — which is exactly why route 2 could not reuse the shared
 *    predicate. THIS IS NOT AN EXEMPTION: that population gets its OWN tripwire below,
 *    [exactlyOneInsertionPointCookieTypePredicateExistsInMainSource], with its own known-positive
 *    fixtures. Two populations, two counts, two owners — not one widened expectation.
 *
 * Comment lines are stripped before matching. A `grep -c`-style count over unstripped source would
 * count the very supersession comments plan 28-02 writes — which is exactly how a header becomes
 * self-invalidating. Stripping is by LINE PREFIX — a line-comment marker, a KDoc continuation star,
 * or a block-comment opener — so a comparison hidden behind a TRAILING comment on a code line is
 * still seen, while a comparison spelled outside the four classes is not.
 *
 * This is a TRIPWIRE OVER MEASURED SPELLINGS, not a proof of exhaustive coverage. Anyone adding a
 * new spelling class must add it to [COOKIE_TYPE_COMPARISONS], or the tripwire silently stops
 * covering their code.
 */
class CookieRouteDispositionTest {
    @Test
    fun exactlyOneCookieTypePredicateExistsInMainSource() {
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the source walk reached ${files.size} .kt files under ${SourceRoots.PRODUCTION}, below the " +
                "floor of $MIN_EXPECTED_MAIN_FILES. A walk that reaches nothing would report a " +
                "clean tree for the same reason a correct tree does; fix the walk before reading " +
                "the count below as evidence.",
        )

        val hits = files.flatMap { file -> cookieTypeComparisonsIn(file).map { SourceRoots.relativePath(file) to it } }

        assertEquals(
            1,
            hits.size,
            "expected exactly ONE cookie-parameter-type comparison in ${SourceRoots.PRODUCTION} — the one " +
                "inside $OWNER's isCookieParameterType. Found ${hits.size}: " +
                hits.joinToString("; ") { "${it.first} -> ${it.second.trim()}" } +
                ". A SECOND cookie-type predicate is how this control gets bypassed without anyone " +
                "editing isCookieParameterType: the new predicate silently acquires its own notion " +
                "of what a cookie parameter is, and the two drift apart exactly as the header rule " +
                "did before phase 27. Route the new call site through Redaction.isCookieParameterType " +
                "instead of widening this expectation.",
        )

        assertEquals(
            OWNER,
            hits.single().first,
            "the single cookie-parameter-type comparison must live in $OWNER, the OWNER of the rule. " +
                "Finding it elsewhere means ownership moved without the KDoc moving with it.",
        )
    }

    @Test
    fun everyCookieTypeComparisonSpellingHasAKnownPositive() {
        COOKIE_TYPE_COMPARISONS.zip(SPELLING_FIXTURES).forEach { (pattern, fixture) ->
            assertTrue(
                pattern.containsMatchIn(fixture),
                "spelling class /${pattern.pattern}/ matched none of its own fixture <$fixture>. A " +
                    "regex that matches nothing reports a clean tree for free, so the count above " +
                    "would be vacuous.",
            )
        }
        assertEquals(
            COOKIE_TYPE_COMPARISONS.size,
            SPELLING_FIXTURES.size,
            "every spelling class needs exactly one known positive, or an unfixtured class can rot " +
                "into a no-op unnoticed.",
        )
    }

    /**
     * The tripwire for the SECOND cookie-type population — the insertion-point one plan 28-05
     * created (route 2 of `AR-27-08`, `CR-02`).
     *
     * Item 3 of the class KDoc's exclusion list states why this cannot be folded into
     * [exactlyOneCookieTypePredicateExistsInMainSource]: the two count comparisons against DIFFERENT
     * closed Montoya enums, and merging them would make one predicate's contract ambiguous and move
     * a count that is evidence for a different claim. So this file now holds two counts with two
     * owners, built from the same parts so a reader meets one idiom rather than two.
     *
     * Same bound as its sibling, restated because it applies just as hard here: this is a TRIPWIRE
     * OVER MEASURED SPELLINGS, not a proof of exhaustive coverage. Anyone adding a new spelling of
     * the insertion-point cookie question must add it to [INSERTION_POINT_COOKIE_TYPE_COMPARISONS],
     * or this tripwire silently stops covering their code.
     */
    @Test
    fun exactlyOneInsertionPointCookieTypePredicateExistsInMainSource() {
        val files = SourceRoots.kotlinFiles()
        assertTrue(
            files.size >= MIN_EXPECTED_MAIN_FILES,
            "the source walk reached ${files.size} .kt files under ${SourceRoots.PRODUCTION}, below the " +
                "floor of $MIN_EXPECTED_MAIN_FILES. A walk that reaches nothing would report a " +
                "clean tree for the same reason a correct tree does; fix the walk before reading " +
                "the count below as evidence.",
        )

        val hits = files.flatMap { file -> insertionPointCookieComparisonsIn(file).map { SourceRoots.relativePath(file) to it } }

        assertEquals(
            1,
            hits.size,
            "expected exactly ONE insertion-point cookie-type predicate in ${SourceRoots.PRODUCTION} — the " +
                "one inside $INSERTION_POINT_OWNER's isCookieInsertionPoint. Found ${hits.size}: " +
                hits.joinToString("; ") { "${it.first} -> ${it.second.trim()}" } +
                ". A SECOND insertion-point cookie predicate is how the route-2 control gets " +
                "bypassed without anyone editing isCookieInsertionPoint: the new predicate " +
                "silently acquires its own notion of what a cookie insertion point is, and the two " +
                "drift apart. Route the new call site through AiScanCheck.isCookieInsertionPoint " +
                "instead of widening this expectation.",
        )

        assertEquals(
            INSERTION_POINT_OWNER,
            hits.single().first,
            "the single insertion-point cookie-type predicate must live in $INSERTION_POINT_OWNER, " +
                "the OWNER of the rule. Finding it elsewhere means ownership moved without the " +
                "KDoc moving with it.",
        )
    }

    /**
     * The non-vacuity half of the tripwire above, mirroring
     * [everyCookieTypeComparisonSpellingHasAKnownPositive].
     *
     * Without it a regex that matched nothing would report a clean tree for free, and the count of
     * one would be satisfied by luck rather than by measurement.
     */
    @Test
    fun everyInsertionPointSpellingHasAKnownPositive() {
        INSERTION_POINT_COOKIE_TYPE_COMPARISONS.zip(INSERTION_POINT_SPELLING_FIXTURES).forEach { (pattern, fixture) ->
            assertTrue(
                pattern.containsMatchIn(fixture),
                "insertion-point spelling class /${pattern.pattern}/ matched none of its own " +
                    "fixture <$fixture>. A regex that matches nothing reports a clean tree for " +
                    "free, so the count above would be vacuous.",
            )
        }
        assertEquals(
            INSERTION_POINT_COOKIE_TYPE_COMPARISONS.size,
            INSERTION_POINT_SPELLING_FIXTURES.size,
            "every insertion-point spelling class needs exactly one known positive, or an " +
                "unfixtured class can rot into a no-op unnoticed.",
        )
    }

    /**
     * D-28-02's NO-DOUBLE-REDACTION boundary, from the extractor's side.
     *
     * This is half (b) of the composition proof: unchanged input plus unchanged code is
     * byte-identical output. Half (a) — that `AdaptivePayloadEngine.kt` is byte-unchanged across
     * phase 28 — is checked by `git diff` and by the file appearing in no plan's `files_modified`,
     * because a test cannot prove a file was never edited.
     */
    @Test
    fun cookieInjectionPointCarriesTheRawValueSoTheControlledConsumerIsNotDoubleRedacted() {
        val point =
            InjectionPointExtractor
                .extract(cookieRequest(RAW_COOKIE_VALUE), emptySet())
                .single { it.type == InjectionType.COOKIE }

        assertEquals(
            RAW_COOKIE_VALUE,
            point.originalValue,
            "InjectionPointExtractor.extract must hand the RAW cookie value to its consumers. It " +
                "returned '${point.originalValue}' instead, which means a redaction control has " +
                "been MOVED INTO THE EXTRACTOR. Per D-28-02 that is the wrong place for it: the " +
                "predicate has two consumers with different dispositions. ActiveAiScanner's " +
                "issue-detail route is controlled at its WRITE site " +
                "(ScannerIssueSupport.sanitizeInjectionPointValue, plan 28-01), and " +
                "AdaptivePayloadEngine is ALREADY controlled — it substitutes its own value marker " +
                "under any non-OFF mode. Redacting here hits both, so the engine's prompt would " +
                "tell the model a value was redacted twice by two different vocabularies. That is " +
                "misleading to the model AND it destroys the attribution that makes each route's " +
                "control independently testable. It also changes what the ACTIVE SCANNER sends as " +
                "a payload baseline, because originalValue is scanner input and not only a " +
                "reporting field. Put the control at the consumer that needs it.",
        )

        assertNotEquals(
            ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER,
            point.originalValue,
            "the extractor emitted the ISSUE-DETAIL route's marker. That control belongs to " +
                "ScannerIssueSupport.sanitizeInjectionPointValue, downstream of here (D-28-02).",
        )
        assertNotEquals(
            adaptiveEngineValueMarker(),
            point.originalValue,
            "the extractor emitted AdaptivePayloadEngine's OWN value marker. The engine applies " +
                "that substitution itself; doing it here too is the double redaction D-28-02 " +
                "exists to prevent.",
        )
    }

    @Test
    fun theAdaptivePayloadPromptCarriesOneMarkerVocabularyUnderBalanced() {
        val prompt = capturedAdaptivePrompt(PrivacyMode.BALANCED)

        assertTrue(
            prompt.contains(adaptiveEngineValueMarker()),
            "AdaptivePayloadEngine's BALANCED prompt must carry its OWN value marker " +
                "'${adaptiveEngineValueMarker()}'. Prompt was: $prompt",
        )
        assertTrue(
            !prompt.contains(ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER),
            "AdaptivePayloadEngine's prompt carries the ISSUE-DETAIL marker " +
                "'${ScannerIssueSupport.INJECTION_VALUE_STRIPPED_MARKER}'. Two markers on one " +
                "route means the value was redacted twice by two vocabularies — see D-28-02. " +
                "Prompt was: $prompt",
        )
    }

    /**
     * ATTRIBUTION CONTROL for the test above. Without it, a prompt that happened never to contain
     * any value at all would satisfy the BALANCED assertions for entirely the wrong reason.
     */
    @Test
    fun theAdaptivePayloadPromptCarriesTheRawValueUnderOff() {
        val prompt = capturedAdaptivePrompt(PrivacyMode.OFF)

        assertTrue(
            prompt.contains(RAW_COOKIE_VALUE),
            "under OFF the engine documents that it passes the raw value through, so the prompt " +
                "must contain '$RAW_COOKIE_VALUE'. If it does not, the BALANCED test above is " +
                "vacuous: it would pass on a prompt that renders no value at all. Prompt was: $prompt",
        )
    }

    /**
     * Drives the real [AdaptivePayloadEngine] and returns the prompt it actually sent.
     *
     * Two vacuity traps are closed here on purpose. The tech-stack seed is asserted to have TAKEN
     * EFFECT, because without it `generateAdaptivePayloads` hits its empty-context early return and
     * every assertion downstream passes on a prompt that was never built. And the supervisor stub
     * invokes `onComplete` synchronously so the engine's `CountDownLatch` releases at once rather
     * than the test sitting on the engine's timeout.
     */
    private fun capturedAdaptivePrompt(mode: PrivacyMode): String {
        ScanKnowledgeBase.clear()
        val host = "cookie-route-disposition.${mode.name.lowercase()}.test"
        ScanKnowledgeBase.recordTechStack(host, setOf("nginx", "php"))
        assertTrue(
            ScanKnowledgeBase.getTechStack(host).isNotEmpty(),
            "the tech-stack seed did not take effect, so generateAdaptivePayloads would return " +
                "early on empty context and this test would prove nothing.",
        )

        val captured = AtomicReference<String?>(null)
        val supervisor =
            mock<AgentSupervisor>(
                defaultAnswer =
                    Answer { invocation ->
                        if (invocation.method.name == "send") {
                            captured.set(invocation.arguments[0] as String)
                            @Suppress("UNCHECKED_CAST")
                            (invocation.arguments[6] as (Throwable?) -> Unit).invoke(null)
                        }
                        null
                    },
            )

        // Return value is deliberately ignored: the stub streams no chunks, so the engine parses an
        // empty response, returns no payloads and caches nothing. The prompt is the artefact.
        AdaptivePayloadEngine(supervisor).generateAdaptivePayloads(
            vulnClass = VulnClass.SSRF,
            host = host,
            paramName = "session",
            originalValue = RAW_COOKIE_VALUE,
            privacyMode = mode,
        )

        ScanKnowledgeBase.clear()
        return requireNotNull(captured.get()) {
            "AdaptivePayloadEngine never called supervisor.send, so no prompt was captured. Do not " +
                "read a passing assertion off a null prompt; fix the harness."
        }
    }

    /**
     * Reads `AdaptivePayloadEngine`'s value marker OUT OF ITS SOURCE rather than restating the
     * literal here. The engine writes it inline instead of exporting a constant, so a test that
     * hardcoded it would keep passing after the engine's marker changed — which is the exact way a
     * marker-vocabulary assertion stops covering the thing it names.
     */
    private fun adaptiveEngineValueMarker(): String {
        val source = SourceRoots.file(ADAPTIVE_ENGINE_PATH)
        assertTrue(source.isFile, "could not read $ADAPTIVE_ENGINE_PATH to derive the engine's value marker.")
        val match =
            ADAPTIVE_VALUE_MARKER_PATTERN.find(source.readText())
                ?: throw AssertionError(
                    "could not find the OFF-mode value substitution in $ADAPTIVE_ENGINE_PATH. The " +
                        "engine's marker vocabulary moved; update ADAPTIVE_VALUE_MARKER_PATTERN " +
                        "rather than hardcoding the marker into this test.",
                )
        return match.groupValues[1]
    }

    private fun cookieRequest(value: String): HttpRequest {
        val param = mock<ParsedHttpParameter>()
        whenever(param.type()).thenReturn(HttpParameterType.COOKIE)
        whenever(param.name()).thenReturn("session")
        whenever(param.value()).thenReturn(value)

        val request = mock<HttpRequest>()
        whenever(request.parameters()).thenReturn(listOf(param))
        whenever(request.headers()).thenReturn(emptyList())
        whenever(request.headerValue("Content-Type")).thenReturn(null)
        whenever(request.bodyToString()).thenReturn("")
        whenever(request.url()).thenReturn("http://example.com/")
        return request
    }

    private fun cookieTypeComparisonsIn(file: File): List<String> = matchingCodeLinesIn(file, COOKIE_TYPE_COMPARISONS)

    private fun insertionPointCookieComparisonsIn(file: File): List<String> = matchingCodeLinesIn(file, INSERTION_POINT_COOKIE_TYPE_COMPARISONS)

    /**
     * Comment stripping is by LINE PREFIX — a line-comment marker, a KDoc continuation star, or a
     * block-comment opener — so a comparison hidden behind a TRAILING comment on a code line is
     * still seen, while the very supersession comments these plans write are not counted. Shared by
     * both populations so the two counts cannot drift apart in how they read a file.
     */
    private fun matchingCodeLinesIn(
        file: File,
        patterns: List<Regex>,
    ): List<String> =
        file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }.filter { line -> patterns.any { it.containsMatchIn(line) } }

    private companion object {
        // Measured at 172 .kt files when this test was written. The floor is deliberately well below
        // that: it is here to catch a walk that reaches nothing, not to track the file count.
        const val MIN_EXPECTED_MAIN_FILES = 150

        /** The OWNER of the cookie-parameter-type rule. */
        const val OWNER = "com/six2dez/burp/aiagent/redact/Redaction.kt"

        const val ADAPTIVE_ENGINE_PATH = "com/six2dez/burp/aiagent/scanner/AdaptivePayloadEngine.kt"

        /**
         * Distinctive enough that finding it in a prompt cannot be a coincidence, and shaped like a
         * real session cookie so a reader sees why leaking it would matter.
         */
        const val RAW_COOKIE_VALUE = "s%3AcookieRouteDisposition-9f13c4ae.RAWVALUE"

        /**
         * `AdaptivePayloadEngine`'s OFF-mode ternary, from which the engine's own value marker is
         * read. Keyed on the `PrivacyMode.OFF` comparison rather than on the marker text, so the
         * pattern survives a rename of the marker — which is the whole point of deriving it.
         */
        val ADAPTIVE_VALUE_MARKER_PATTERN = Regex("""privacyMode != PrivacyMode\.OFF\)\s*"([^"]+)"""")

        /**
         * The ways a Montoya parameter TYPE is compared against the COOKIE constant in this codebase.
         * Case-sensitive: the Montoya enum name is uppercase, and a case-insensitive scan would also
         * pick up the lowercase HEADER-name rules, which are a different control with a different
         * owner (see `CookieHeaderRuleOwnershipTest`).
         *
         * See the class KDoc for what this population deliberately EXCLUDES.
         */
        val COOKIE_TYPE_COMPARISONS =
            listOf(
                // literal equality/inequality, predicate on the left
                Regex("[=!]= \"COOKIE\""),
                // literal equality/inequality, predicate on the right
                Regex("\"COOKIE\" [=!]="),
                // equals-call form, with or without `ignoreCase`
                Regex("equals\\(\"COOKIE\""),
                // equality against the owner's constant — the one legitimate hit
                Regex("[=!]= COOKIE_PARAMETER_TYPE_NAME"),
            )

        /** One known positive per spelling class, so a regex that matches nothing cannot hide. */
        val SPELLING_FIXTURES =
            listOf(
                """.filter { it.type().name == "COOKIE" }""",
                """if ("COOKIE" == param.type().name) return true""",
                """if (typeName.equals("COOKIE", ignoreCase = true)) return true""",
                """typeName.trim().uppercase(Locale.ROOT) == COOKIE_PARAMETER_TYPE_NAME""",
            )

        /** The OWNER of the INSERTION-POINT cookie-type rule (plan 28-05, route 2 of `AR-27-08`). */
        const val INSERTION_POINT_OWNER = "com/six2dez/burp/aiagent/scanner/AiScanCheck.kt"

        /**
         * The ways a Montoya AUDIT INSERTION POINT type is compared against its cookie constant in
         * this codebase — a population disjoint from [COOKIE_TYPE_COMPARISONS] by construction, see
         * item 3 of the class KDoc.
         *
         * Identity comparisons against a member of the closed `AuditInsertionPointType` enum, in
         * either operand order. Deliberately keyed on the QUALIFIED constant rather than on a bare
         * `PARAM_COOKIE`: an unqualified spelling would also match an import alias or an unrelated
         * enum that happened to share the member name, and this count is only meaningful if every
         * hit is the same question being asked twice.
         *
         * D-28-07's discipline is what makes this population small: the decision is taken on a
         * closed-enum MEMBER, never on a rendered string, so there is no `.name`-comparison spelling
         * to enumerate here at all. If one ever appears, it belongs in this list AND it is a signal
         * that route 2 has drifted back toward the shape phase 27 measured as structurally blind.
         */
        val INSERTION_POINT_COOKIE_TYPE_COMPARISONS =
            listOf(
                // identity comparison, constant on the right
                Regex("""[=!]= AuditInsertionPointType\.PARAM_COOKIE"""),
                // identity comparison, constant on the left
                Regex("""AuditInsertionPointType\.PARAM_COOKIE [=!]="""),
            )

        /**
         * One known positive per insertion-point spelling class.
         *
         * These fixtures necessarily CONTAIN the literal `AuditInsertionPointType`, which makes this
         * file the second under `src/test/kotlin/` to do so. That is expected and not a regression:
         * the scan walks the production roots only (`src/main/kotlin` and `src/full/kotlin`, through
         * SourceRoots), so a fixture here can never be counted by the tripwire it protects.
         */
        val INSERTION_POINT_SPELLING_FIXTURES =
            listOf(
                """insertionPoint.type() == AuditInsertionPointType.PARAM_COOKIE""",
                """if (AuditInsertionPointType.PARAM_COOKIE == point.type()) return true""",
            )
    }
}
