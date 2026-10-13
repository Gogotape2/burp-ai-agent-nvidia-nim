package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * QUAL-07 / SC4 — `ChatPanel`'s EDT check says what it actually does, and keeps saying it.
 *
 * **This suite is structural on purpose, and the purpose is the decision behind it.** SC4 asked for one
 * of two honest end states for `ChatPanel.assertEdt()`: a mechanism that reports inside a shipped Burp,
 * or source that states plainly that it does not. Phase 26 plan 26-04 selected the second
 * (`document-test-only`); `26-04-SUMMARY.md` § `SC4 decision` carries the selection verbatim along with
 * the measurement it was taken against. So there is no new runtime behaviour to assert here — the whole
 * deliverable is the wording, and wording is exactly the kind of thing that rots silently.
 *
 * **Why a test rather than a comment.** The state SC4 exists to end is not "the check is weak"; it is
 * "the check reads as a guarantee it does not provide". That gap opened once already, through ordinary
 * drift: the helper is named `assertEdt`, its summary line claimed it asserted EDT-ness, and the call
 * site at `maybeExecuteToolCall` said the rule was "enforced by assertEdt() under -ea" — while the JVM
 * disables the debug-time assertion facility in every Burp a user actually runs. Nothing stops that
 * wording coming back except an assertion that fails when it does.
 *
 * **What this suite does NOT claim.** It does not claim the EDT-confinement invariant is enforced in
 * the field, because under the selected option it is not. The invariant is held by the marshalling
 * discipline at the callers and proved by `ChatPanelEdtConfinementTest`; this file only pins the
 * honesty of the surrounding prose. Anyone reading these assertions as safety evidence has read them
 * backwards.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is what `.github/workflows/build.yml`'s PR gate passes. Any of those suffixes here would make
 * this suite nightly-only. Do not rename this class into one of them.
 *
 * `ChatPanel.kt` is covered by `tasks.test`'s `inputs.dir("src/main/kotlin")` declaration, so these
 * assertions really do re-run when the source text changes even when the bytecode does not — the 22-09
 * stale-cache defect. No build-file change is needed to make that true.
 */
class ChatPanelEdtGuardTest {
    /**
     * SC4, first limb — the helper's own KDoc states it has no effect in a shipped Burp.
     *
     * Four markers rather than one loose phrase, because each carries a different half of the statement
     * SC4 asks for: what the mechanism IS ([DEVELOPMENT_TIME_MARKER]), which JVM it is absent from
     * ([SHIPPED_BURP_MARKER]), what that absence amounts to ([NO_PRODUCTION_EFFECT_MARKER]), and what to
     * do instead ([REMEDY_MARKER]). A KDoc carrying three of the four would still leave a reader
     * guessing at the fourth, which is the state this criterion exists to end.
     */
    @Test
    fun theEnforcementHelperKDocStatesItHasNoEffectInShippedBurp() {
        val kdoc = enforcementHelperKDoc()

        listOf(
            DEVELOPMENT_TIME_MARKER,
            SHIPPED_BURP_MARKER,
            NO_PRODUCTION_EFFECT_MARKER,
            REMEDY_MARKER,
        ).forEach { marker ->
            assertTrue(
                kdoc.contains(marker),
                "QUAL-07 / SC4: the KDoc on ChatPanel's EDT check must contain `$marker`. Under the " +
                    "`document-test-only` disposition the wording IS the deliverable — the mechanism " +
                    "is unchanged, so a KDoc that stops saying this leaves the file back in the state " +
                    "SC4 exists to end. KDoc was:\n$kdoc",
            )
        }
    }

    /**
     * SC4, second limb — the KDoc no longer opens by claiming the check asserts EDT-ness outright.
     *
     * The negative half, and without it the test above is satisfiable by appending a disclaimer under a
     * summary line that still reads as a guarantee. A KDoc's first sentence is what a reader takes from
     * it and what an IDE surfaces on hover, so a bare guarantee there outweighs any correction below.
     */
    @Test
    fun theEnforcementHelperKDocDoesNotOpenWithABareGuarantee() {
        val kdoc = enforcementHelperKDoc()

        assertTrue(
            !kdoc.contains(BARE_GUARANTEE_SUMMARY),
            "QUAL-07 / SC4: the KDoc must not carry the summary line `$BARE_GUARANTEE_SUMMARY`. It " +
                "states a runtime guarantee the JVM does not provide without -ea, and a correction " +
                "further down does not undo a first sentence. KDoc was:\n$kdoc",
        )
    }

    /**
     * SC4 at the tracer call site — `maybeExecuteToolCall` does not claim field enforcement.
     *
     * This is the site plan 26-04 converted first, end to end, before the other three. The phrases in
     * [FIELD_ENFORCEMENT_CLAIMS] are the ones that make a reader believe a violation would be caught;
     * "enforced by assertEdt() under -ea" was the literal wording here before this plan.
     */
    @Test
    fun theToolCallSiteDoesNotClaimTheCheckEnforcesConfinement() {
        assertNoFieldEnforcementClaim(MAYBE_EXECUTE_TOOL_CALL)
    }

    /**
     * SC4 at the tracer call site — the prose names the remedy, not only the rule.
     *
     * A guard that says a rule was broken and not what to do instead makes whoever meets it guess, which
     * is the objection `McpToolExecutorImpl`'s production door guard already answers by naming
     * `OffEdtDispatch.run` in its own failure message. The same standard applies to prose that stands in
     * for a guard.
     */
    @Test
    fun theToolCallSiteNamesTheMarshallingRemedy() {
        assertNamesTheRemedy(MAYBE_EXECUTE_TOOL_CALL)
    }

    /**
     * SC4's uniformity clause — all four sites carry the same honest framing, none is left behind.
     *
     * **A partial conversion is the worst outcome available here, and this is the assertion that
     * rejects it.** Plan 26-04's prohibition list names it directly: a file where the same-looking
     * helper means different things at different call sites is worse than either end state, because a
     * reader who checks one site generalises to the rest. Asserting the four together, in one test that
     * iterates [GUARDED_CALL_SITES], is what makes "all four" a claim rather than three separate claims
     * that happen to coexist.
     */
    @Test
    fun allFourGuardedCallSitesCarryTheSameHonestFraming() {
        GUARDED_CALL_SITES.forEach { declaration ->
            assertNoFieldEnforcementClaim(declaration)
            assertNamesTheRemedy(declaration)
        }
    }

    /**
     * SC4's uniformity clause, mechanism half — one mechanism, at exactly four sites, with no rival.
     *
     * **The test above pins the prose; this one pins the code the prose describes, and neither is
     * sufficient alone.** A half-applied upgrade would leave some sites on `assert(...)` and others on
     * a throwing `check(...)`, and the prose assertions would not notice — both shapes are compatible
     * with any wording. Equally, counting invocations without reading the prose is how the file reached
     * the state SC4 exists to end in the first place.
     *
     * The invocation count is line-based rather than a substring tally on purpose: a bare
     * `occurrencesOf("assertEdt()")` also counts the declaration and every comment that names the
     * helper, so it would move on prose alone. Counting lines whose entire content is the call counts
     * call sites and nothing else.
     */
    @Test
    fun theFileCarriesOneEdtMechanismAcrossExactlyFourCallSites() {
        val source = chatPanelSource()

        val invocations = source.lines().count { it.trim() == "$HELPER_NAME()" }
        assertTrue(
            invocations == GUARDED_CALL_SITES.size,
            "QUAL-07 / SC4: expected exactly ${GUARDED_CALL_SITES.size} invocations of `$HELPER_NAME()` " +
                "in ChatPanel.kt, found $invocations. FEWER means a call site lost its check while the " +
                "prose around it still describes one. MORE means a site was added without a matching " +
                "entry in GUARDED_CALL_SITES, so the uniformity assertions above silently stopped " +
                "covering the whole set.",
        )
        assertTrue(
            source.lines().count { it.trim().startsWith("private fun $HELPER_NAME()") } == 1,
            "QUAL-07 / SC4: ChatPanel.kt must declare exactly one EDT check helper. Two would be the " +
                "partial-upgrade state by another route.",
        )
        assertTrue(
            !source.contains(RIVAL_MECHANISM),
            "QUAL-07 / SC4: ChatPanel.kt must not contain `$RIVAL_MECHANISM` alongside the existing " +
                "helper — that is two EDT mechanisms in one file, which plan 26-04's prohibition list " +
                "rejects because the same-looking guard would then mean different things at different " +
                "call sites. If the `upgrade-throwing-check` disposition is being adopted after all, " +
                "convert ALL FOUR sites, move ChatPanelEdtConfinementTest's byte-identical pin and its " +
                "mention counter, and add this class to edtGuardWithoutAssertionsTest's filter so the " +
                "new mechanism is proved under -da rather than only under tasks.test's -ea.",
        )
    }

    private fun assertNoFieldEnforcementClaim(declaration: String) {
        val narrative = guardNarrative(declaration)

        FIELD_ENFORCEMENT_CLAIMS.forEach { claim ->
            assertTrue(
                !narrative.contains(claim),
                "QUAL-07 / SC4: the prose around `$declaration` must not contain `$claim`. Under the " +
                    "`document-test-only` disposition the check is a development-time aid the JVM " +
                    "disables without -ea, so any wording that tells a reader a violation would be " +
                    "caught is false in every shipped Burp. Say what holds the invariant instead — the " +
                    "caller's marshalling. Prose was:\n$narrative",
            )
        }
    }

    private fun assertNamesTheRemedy(declaration: String) {
        val narrative = guardNarrative(declaration)

        assertTrue(
            narrative.contains(REMEDY_MARKER),
            "QUAL-07 / SC4: the prose around `$declaration` must name `$REMEDY_MARKER` — the thing a " +
                "caller does instead of relying on a check that does not run. Naming only the rule " +
                "leaves whoever meets it to guess, which is the objection McpToolExecutorImpl's " +
                "production door guard already answers by naming OffEdtDispatch.run. Prose was:\n" +
                narrative,
        )
    }

    /**
     * The KDoc block attached to the enforcement helper, asserted to be genuinely attached.
     *
     * **The adjacency check is what stops this suite going vacuous.** A backwards search for a KDoc opener finds
     * *a* KDoc whether or not it belongs to the declaration, so without it a refactor that dropped the
     * helper's own KDoc would silently start asserting against whichever block sat above the gap — and
     * every marker test would keep passing against someone else's prose.
     */
    private fun enforcementHelperKDoc(): String {
        val source = chatPanelSource()
        val declaration = "private fun $HELPER_NAME()"
        val declarationIndex = source.indexOf(declaration)
        assertTrue(
            declarationIndex >= 0,
            "No `$declaration` in ChatPanel.kt — this structural assertion is stale.",
        )
        val kdoc = precedingKDocOrEmpty(source, declarationIndex)
        assertTrue(
            kdoc.isNotEmpty(),
            "No KDoc is attached to `$declaration` in ChatPanel.kt. Under the `document-test-only` " +
                "disposition that KDoc is the entire deliverable — without it there is nothing telling " +
                "a reader the check does not run in shipped Burp.",
        )
        return kdoc
    }

    /**
     * Everything a reader sees about the EDT rule at [declaration]: its KDoc plus any comment inside the
     * body before the check itself.
     *
     * Both halves, because the four sites do not put the explanation in the same place — some carry it
     * in a KDoc above the signature and some in a comment just inside the brace. Reading only one half
     * would make the assertions pass or fail on where a comment happens to sit rather than on what it
     * says.
     */
    private fun guardNarrative(declaration: String): String {
        val source = chatPanelSource()
        val declarationIndex = source.indexOf(declaration)
        assertTrue(
            declarationIndex >= 0,
            "No `$declaration` in ChatPanel.kt — this structural assertion is stale.",
        )
        val open = source.indexOf('{', declarationIndex)
        val checkIndex = source.indexOf("$HELPER_NAME()", open)
        assertTrue(
            checkIndex in (open + 1)..(open + MAX_PROLOGUE_CHARS),
            "Expected `$HELPER_NAME()` within the first $MAX_PROLOGUE_CHARS characters of " +
                "`$declaration`'s body. Found at offset ${checkIndex - open}. Either the check moved " +
                "away from the top of the function — where it has to be to guard anything — or this " +
                "lookup is stale and the prose being asserted belongs to some later statement.",
        )
        return precedingKDocOrEmpty(source, declarationIndex) + "\n" + source.substring(open, checkIndex)
    }

    /** The KDoc attached to the declaration at [declarationIndex], or `""` when there is none. */
    private fun precedingKDocOrEmpty(
        source: String,
        declarationIndex: Int,
    ): String {
        val close = source.lastIndexOf("*/", declarationIndex)
        if (close < 0 || source.substring(close + 2, declarationIndex).isNotBlank()) return ""
        val open = source.lastIndexOf("/**", close)
        return if (open < 0) "" else source.substring(open, close + 2)
    }

    /**
     * `ChatPanel.kt`'s source text.
     *
     * Resolved through [SourceRoots.file], which fails naming both production roots rather than letting
     * a build-layout change surface as a bare `FileNotFoundException`.
     */
    private fun chatPanelSource(): String = SourceRoots.file(CHAT_PANEL_SOURCE_PATH).readText()

    private companion object {
        const val CHAT_PANEL_SOURCE_PATH = "com/six2dez/burp/aiagent/ui/ChatPanel.kt"

        /** The EDT check's name. Kept in one place so a rename fails loudly here rather than silently. */
        const val HELPER_NAME = "assertEdt"

        const val MAYBE_EXECUTE_TOOL_CALL = "private fun maybeExecuteToolCall("

        /**
         * The four `@GuardedBy("EDT")` entry points the check guards.
         *
         * This list IS the uniformity claim: every assertion that says "all four" iterates it, so a
         * fifth site added without an entry here would leave the new site uncovered. That is caught by
         * [theFileCarriesOneEdtMechanismAcrossExactlyFourCallSites]'s invocation count rather than
         * being left to whoever notices, which is what stops this list quietly going stale.
         *
         * [MAYBE_EXECUTE_TOOL_CALL] appears here and separately above because it is the tracer site —
         * plan 26-04 converted it first, end to end, and its two dedicated tests are what proved the
         * proof mechanism worked while only one site was in flight.
         */
        val GUARDED_CALL_SITES =
            listOf(
                "fun cancelInFlightRequest()",
                "private fun syncDraftFromInput()",
                MAYBE_EXECUTE_TOOL_CALL,
                "private fun resolveToolDecision(",
            )

        /** A throwing EDT check — the `upgrade-throwing-check` shape, which was NOT selected. */
        const val RIVAL_MECHANISM = "check(SwingUtilities.isEventDispatchThread())"

        /** What the mechanism is: an aid used while developing, not a control that ships. */
        const val DEVELOPMENT_TIME_MARKER = "development-time"

        /** The JVM the absence is about — the one a user actually runs the extension in. */
        const val SHIPPED_BURP_MARKER = "shipped Burp"

        /** The absence stated in as many words, which is precisely what SC4's second limb asks for. */
        const val NO_PRODUCTION_EFFECT_MARKER = "no production effect"

        /** What a caller does instead. The remedy, in the style the executor's door guard already uses. */
        const val REMEDY_MARKER = "invokeAndWait"

        /** The summary line that made the helper read as a guarantee before plan 26-04. */
        const val BARE_GUARANTEE_SUMMARY = "Asserts that the calling code is on the AWT Event Dispatch Thread"

        /**
         * Wordings that tell a reader a violation would be caught in the field. None is true under the
         * selected disposition, and "enforced by" was the literal wording at `maybeExecuteToolCall`.
         */
        val FIELD_ENFORCEMENT_CLAIMS =
            listOf(
                "enforced by",
                "guaranteed by",
                "prevented by",
                "enforces this",
            )

        /**
         * How far into a body the check may sit and still be guarding it.
         *
         * Generous enough for the explanatory comment some of the four sites carry inside the brace,
         * tight enough that a check drifting below real work fails instead of being silently accepted.
         */
        const val MAX_PROLOGUE_CHARS = 1200
    }
}
