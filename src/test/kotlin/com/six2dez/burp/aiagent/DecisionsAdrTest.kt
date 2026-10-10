package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The sentence future tool authors inherit, declared ONCE so the two copies it guards cannot both be
 * edited to agree with each other while drifting from what was decided.
 *
 * It deliberately starts at "means" rather than at "AUTO": the repo-root `DECISIONS.md` writes the
 * subject as the markdown literal `` `AUTO` `` and the `SecTier` KDoc writes it as the KDoc link
 * `[AUTO]`, so the leading token is the one part the two copies legitimately differ on. Everything
 * after it is the rule itself and must be byte-identical once markup is normalised away.
 */
private const val AUTO_DEFINITION: String =
    "means read-only AND bounded output. A tool qualifies only if it neither mutates Burp state " +
        "nor pulls bulk attacker-controlled traffic into model context"

private const val DECISIONS_FILE = "DECISIONS.md"
private const val CATALOG_FILE = "com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt"

/**
 * The number of `Residual:` bullets ADR-16 actually ships, and therefore the bound below which the
 * guard below stops meaning what its own comment says.
 *
 * It sat at 5 against 6 shipped bullets from phase 25 until phase 26 (25-REVIEW IN-02): a bound one
 * below the shipped count cannot catch the deletion of exactly one bullet, which is the only deletion
 * an editing accident ever produces. Phase 26 added the seventh bullet and raised this to 7 in the
 * same commit. Keep the two EQUAL: raising it above the shipped count makes the suite red for no
 * reason, and lowering it below re-opens the gap.
 */
private const val MIN_ADR16_RESIDUALS = 7

/**
 * SEC-06 / SC1 guard on ADR-15 — the written rule by which a tool added in a later phase inherits the
 * trust boundary instead of re-litigating it — since phase 25 the SEC-07 guard on ADR-16, and since
 * phase 26 the QUAL-07 guard on ADR-17.
 *
 * **What this test can do.** It is a string-match guard. It stops ADR-15 from disappearing, stops it
 * from silently losing D-05's `AUTO` sentence in a later edit, and — the part that carries the real
 * value — asserts that the ADR's copy and the [com.six2dez.burp.aiagent.mcp.SecTier] KDoc's copy still
 * say the same thing. Two divergent copies of the inherited rule is the failure mode here; a match
 * against one copy alone would not catch it, because the drift would simply move into the other.
 *
 * **What this test cannot do.** It cannot judge whether ADR-15 is *factually accurate* — whether the
 * threat model it records matches shipped behaviour, and whether it claims only what ships (D-14).
 * That is judgement, not a string match, and it is assigned to a human in
 * `.planning/phases/22-agent-tool-call-trust-boundary/22-HUMAN-UAT.md` test 2. Neither half is
 * sufficient alone: an ADR is the one success criterion that is easy to mark done without checking,
 * which is why SC1 carries both a cheap automated guard and an explicit human reviewer.
 */
class DecisionsAdrTest {
    @Test
    fun adr17ExistsAndIsTheHighestNumberedAdr() {
        val decisions = readProjectFile(DECISIONS_FILE)

        assertTrue(
            decisions.lineSequence().any { it.startsWith("## ADR-15") },
            "$DECISIONS_FILE must contain a heading line starting `## ADR-15`. ADR-15 is SEC-06's " +
                "record of the agent tool-call trust boundary; if it was renumbered, the guards below " +
                "and 22-HUMAN-UAT.md both point at nothing.",
        )
        assertTrue(
            decisions.lineSequence().any { it.startsWith("## ADR-16") },
            "$DECISIONS_FILE must contain a heading line starting `## ADR-16`. ADR-16 is SEC-07's " +
                "record of the MCP takeover credential and the loopback certificate pin; without it " +
                "the phase's accepted residuals survive only in `.planning/`, which does not ship.",
        )
        assertTrue(
            decisions.lineSequence().any { it.startsWith("## ADR-17") },
            "$DECISIONS_FILE must contain a heading line starting `## ADR-17`. ADR-17 is QUAL-07's " +
                "record of three dispositions phase 26 took — the detekt baseline's direction, the " +
                "disposition of `ChatPanel`'s EDT enforcement, and what `SecretCipher`'s at-rest " +
                "property actually is. ADR-15's `assertEdt()` residual points here, so deleting it " +
                "strands that pointer.",
        )
        assertFalse(
            decisions.lineSequence().any { it.startsWith("## ADR-18") },
            "$DECISIONS_FILE contains `## ADR-18`, so ADR-17 is no longer the highest-numbered ADR. " +
                "This assertion exists to make the NEXT phase's author notice they must claim a new " +
                "number and extend this guard, rather than quietly reusing one.",
        )
    }

    @Test
    fun adr17NamesAllThreeDispositionsItRecords() {
        val section = adrSection("## ADR-17")

        // The heading alone is worthless: an edit that keeps `## ADR-17` while emptying it would leave
        // the assertion above green and the record gone. Each subject below is named by the symbol or
        // file the clause is ABOUT, so a rewording survives and a removal does not.
        val subjects =
            mapOf(
                "detekt-baseline.xml" to
                    "clause 1 — the rule that the baseline shrinks and is never appended to. Without " +
                    "it a future contributor has no written answer to \"may I just baseline this?\"",
                "assertEdt" to
                    "clause 2 — the disposition of `ChatPanel`'s EDT enforcement, including that the " +
                    "selection was auto-selected by the harness before the user accepted it, and " +
                    "the off-EDT `shutdown()` residual the probe could not retire.",
                "SecretCipher" to
                    "clause 3 — what the AES-256-GCM envelope does and does not protect. ADR-16's " +
                    "filesystem-read residual depends on this statement being here and correct.",
            )
        subjects.forEach { (symbol, why) ->
            assertTrue(
                section.contains(symbol),
                "ADR-17 no longer names `$symbol`, so it has lost $why",
            )
        }
        assertTrue(
            section.contains("Burp Preferences"),
            "ADR-17 clause 3 must say where `SecretCipher`'s master key lives — Base64-encoded in a " +
                "Burp Preferences entry, beside the ciphertext it protects. That location is the " +
                "whole reason the at-rest property is bounded the way it is; an at-rest claim with " +
                "the storage location removed reads as stronger than what ships.",
        )
        assertTrue(
            section.contains("document-test-only"),
            "ADR-17 clause 2 must carry the SC4 selection verbatim as it appears in " +
                "`26-04-SUMMARY.md`. A paraphrased decision is a second decision, made by whoever " +
                "paraphrased it.",
        )
    }

    @Test
    fun adr16RecordsEveryResidualItAccepts() {
        val section = adrSection("## ADR-16")
        val residuals = section.lineSequence().count { it.contains("Residual:") }

        // T-25-17: a residual that is accepted but not written down is indistinguishable from a
        // residual nobody noticed. ADR-16 ships seven, and they are enumerated here so this comment
        // cannot drift from the file it guards - which is the drift the guard exists to catch:
        //   1. proof replay inside the validity window (25-01 T-25-04)
        //   2. host-string identity (25-01 A-25-05)
        //   3. version skew (25-01 A-25-06)
        //   4. filesystem read defeats the pin
        //   5. fail-closed takeover under TLS (T-25-16)
        //   6. the SSRF half of SEC-07 stays advisory (plan 25-02)
        //   7. offline token guessing from a captured proof (25-REVIEW WR-01, added by phase 26)
        // Deleting one from the ADR must be a deliberate act with a red test in front of it, not an
        // editing accident.
        assertTrue(
            residuals >= MIN_ADR16_RESIDUALS,
            "ADR-16 lists $residuals `Residual:` bullets, fewer than the $MIN_ADR16_RESIDUALS this " +
                "phase accepted. If a residual was genuinely closed, close it here deliberately and " +
                "lower this bound in the same commit.",
        )
    }

    @Test
    fun adr15CarriesTheAutoDefinitionVerbatim() {
        val normalised = normalise(adr15Section())

        assertTrue(
            normalised.contains(AUTO_DEFINITION),
            "ADR-15 no longer carries D-05's `AUTO` definition verbatim. This sentence is the rule " +
                "future tool authors inherit; if it changed, the classification changed, and ADR-15 " +
                "must be revised deliberately rather than incidentally. Expected to find:\n  " +
                AUTO_DEFINITION,
        )
    }

    @Test
    fun theCatalogAndTheAdrCarryTheSameAutoDefinition() {
        val kdoc = normalise(secTierKdoc())

        assertTrue(
            kdoc.contains(AUTO_DEFINITION),
            "The `SecTier` KDoc in $CATALOG_FILE no longer states the same `AUTO` definition as " +
                "ADR-15. The rule lives in two places by design — the ADR is what a contributor " +
                "reads, the KDoc is what they see at the point of writing `secTier = ` — and two " +
                "copies that disagree is worse than one, because each looks authoritative. Fix both " +
                "or neither. Expected to find:\n  " + AUTO_DEFINITION,
        )
    }

    @Test
    fun adr15RecordsTheIndependenceFromUnsafeOnly() {
        val section = adr15Section()

        assertTrue(
            section.contains("capability switch"),
            "ADR-15 must keep D-01's crux sentence — that `unsafeOnly` is a capability switch, not a " +
                "trust model. It is the answer to the question a future contributor will otherwise " +
                "get wrong: why are there two classifications?",
        )
        assertTrue(
            section.contains("unsafeOnly"),
            "ADR-15 must name `unsafeOnly` explicitly when recording that the SEC-06 tier is a " +
                "second, independent axis (D-01).",
        )
    }

    /**
     * Reads a file relative to the Gradle project directory.
     *
     * `tasks.test` runs with the project directory as its working directory, so a plain relative path
     * resolves. The existence assertion names the resolved working directory rather than letting a
     * future build-layout change surface as an unhelpful null or empty string.
     */
    private fun readProjectFile(relativePath: String): String {
        val file = File(relativePath)
        assertTrue(
            file.isFile,
            "Expected to find `$relativePath` relative to the test working directory " +
                "`${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`. " +
                "If the build layout changed, fix the path here rather than deleting this test — " +
                "it is the only automated check that ADR-15 still exists.",
        )
        return file.readText()
    }

    /**
     * ADR-15's own text, sliced from its heading to the next `## ADR` heading or end of file, so an
     * assertion cannot be satisfied by wording that belongs to a different ADR.
     */
    private fun adr15Section(): String = adrSection("## ADR-15")

    /**
     * The named ADR's own text, sliced from its heading to the next `## ADR` heading or end of file.
     */
    private fun adrSection(heading: String): String {
        val decisions = readProjectFile(DECISIONS_FILE)
        val start = decisions.indexOf(heading)
        assertTrue(start >= 0, "$DECISIONS_FILE contains no `$heading` heading to slice.")
        val next = decisions.indexOf("\n## ADR", start + 1)
        return if (next >= 0) decisions.substring(start, next) else decisions.substring(start)
    }

    /**
     * The KDoc block immediately preceding `enum class SecTier(`, sliced by locating the declaration
     * and walking back to its opening delimiter. Slicing rather than searching the whole file matters: the
     * assertion must be about the KDoc a contributor reads at the declaration, not about the sentence
     * happening to appear anywhere in a 1000-line catalog.
     */
    private fun secTierKdoc(): String {
        val catalog = SourceRoots.file(CATALOG_FILE).readText()
        val declaration = catalog.indexOf("enum class SecTier(")
        assertTrue(declaration >= 0, "$CATALOG_FILE no longer declares `enum class SecTier(`.")
        val kdocStart = catalog.lastIndexOf("/**", declaration)
        assertTrue(kdocStart >= 0, "`enum class SecTier(` in $CATALOG_FILE has no preceding KDoc block.")
        return catalog.substring(kdocStart, declaration)
    }

    /**
     * Strips the two markup channels that legitimately differ between the copies — markdown blockquote
     * markers and emphasis (`>`, `*`) and KDoc leading asterisks — then collapses every whitespace run
     * to a single space so a line wrap in either file is not a false failure.
     *
     * Neither stripped character appears in [AUTO_DEFINITION], so this normalisation cannot manufacture
     * a match that the source text does not contain.
     */
    private fun normalise(raw: String): String = raw.replace(Regex("[>*]"), "").replace(Regex("\\s+"), " ").trim()
}
