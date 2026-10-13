package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * SC6 — the evidence tail of [ResponseAnalyzer], MEASURED rather than assumed.
 *
 * `VulnConfirmation.evidence` is built by concatenating a per-vuln-class signature label with a
 * MATCHED SUBSTRING of the response text, and `ResponseAnalyzer.analyze` builds that response text
 * from `headers() + "\n\n" + bodyToString()` (`ResponseAnalyzer.kt:619`). Response headers include
 * `Set-Cookie`, so a cookie value is inside the matched-against text. That is the reach question
 * this class answers in BOTH directions.
 *
 * WHAT THIS CLASS IS NOT. It is not a control. Phase 28 files this tail as residual `AR-28-01`;
 * nothing here redacts anything. These are measurements whose numbers feed that register row, plus
 * a drift tripwire so a fourth construction site — or a changed cap — turns this red instead of
 * silently invalidating the recorded severity.
 *
 * THE BOUND THE PRIOR RECORDS STATE IS WRONG. Both `.planning/ROADMAP.md` and
 * `CookieCarrierInventoryTest`'s RESPONSE_ANALYZER/HEADER_LIST disposition say the tail is "capped
 * at 80 characters", singular. The tree has THREE construction sites and they do not agree. This
 * class DERIVES the set from source; the pinned expectation below is a tripwire, not the source of
 * truth, and a derivation that disagrees with the pin is itself the finding.
 */
class EvidenceTailReachTest {
    /**
     * MEASUREMENT A — the cap set, derived by walking the source.
     *
     * Comment lines are stripped first so a cap quoted in prose (this file's own KDoc quotes 80)
     * cannot inflate the count. The failure message carries the measured values so a drift is
     * diagnosable from the report alone, without re-running the walk by hand.
     */
    @Test
    fun theEvidenceTailCapsAreMeasuredNotAssumed() {
        val sites = measureEvidenceConstructionSites()

        assertEquals(
            EXPECTED_SITE_COUNT,
            sites.size,
            "evidence-construction site count changed in $RESPONSE_ANALYZER_PATH. " +
                "Measured ${sites.size} at ${sites.map { it.line }}, pinned $EXPECTED_SITE_COUNT. " +
                "A new site changes the reach recorded for AR-28-01 — re-measure it, do not " +
                "re-pin this number.",
        )

        assertEquals(
            EXPECTED_CAPS_SORTED,
            sites.map { it.cap }.sorted(),
            "evidence-tail cap multiset changed. Measured " +
                "${sites.map { "${it.line}=take(${it.cap})" }}, pinned $EXPECTED_CAPS_SORTED. " +
                "If your derivation disagrees with the pin, THAT is the finding: record the " +
                "derived values raw and say which side moved.",
        )

        // The bound correction, asserted rather than merely narrated: the prior records state a
        // SINGLE cap of 80. If the measured set ever collapses to one value this assertion is the
        // thing that tells a future round the correction can be retired.
        assertTrue(
            sites.map { it.cap }.distinct().size > 1,
            "the measured cap set collapsed to a single value ${sites.map { it.cap }.distinct()}. " +
                "The ROADMAP's and CookieCarrierInventoryTest's 'capped at 80 characters' would " +
                "then finally describe the control, and the AR-28-01 bound correction should be " +
                "superseded in 26-SECURITY.md rather than left standing.",
        )
    }

    /**
     * MEASUREMENT B — reach, in BOTH directions.
     *
     * A one-directional assertion here cannot distinguish "the cookie value is unreachable" from
     * "my fixture never drove the analyzer at all". So the NEGATIVE case still asserts a
     * confirmation was produced: the analyzer demonstrably ran and produced evidence, and that
     * evidence simply does not contain the ordinary session token. The POSITIVE case then shows the
     * same machinery DOES carry the value through when the value itself matches a signature.
     */
    @Test
    fun aCookieValueReachesEvidenceOnlyByMatchingAVulnSignature() {
        val analyzer = ResponseAnalyzer()
        val payload =
            Payload(
                value = "' OR 1=1--",
                vulnClass = VulnClass.SQLI,
                detectionMethod = DetectionMethod.ERROR_BASED,
                risk = PayloadRisk.SAFE,
                expectedEvidence = "SQL error",
            )

        // NEGATIVE — an ordinary session-token-shaped cookie value alongside a real SQL error in the
        // body. The analyzer fires (confirmation is non-null) but the matched span is the body's
        // error text, not the cookie.
        val benignConfirmation =
            analyzer.analyze(
                original = responseWith(SET_COOKIE_BENIGN, "welcome back"),
                modified = responseWith(SET_COOKIE_BENIGN, "You have an error in your SQL syntax near '1=1'"),
                payload = payload,
                vulnClass = VulnClass.SQLI,
            )

        assertNotNull(
            benignConfirmation,
            "NON-VACUITY CONTROL FAILED: the negative fixture produced no confirmation at all, so " +
                "'the cookie value did not reach evidence' would prove nothing. Fix the fixture " +
                "before trusting the negative result.",
        )
        assertFalse(
            benignConfirmation.evidence.contains(BENIGN_COOKIE_VALUE),
            "an ordinary session-token cookie value reached VulnConfirmation.evidence: " +
                "'${benignConfirmation.evidence}'",
        )
        // Pinned verbatim so the SUMMARY's recorded outcome and the tree cannot drift apart
        // silently: the label comes from the ErrorPattern, the quoted span from match.value.
        assertEquals(
            "MySQL syntax error: 'You have an error in your SQL syntax'",
            benignConfirmation.evidence,
            "the negative fixture's evidence shape changed",
        )

        // POSITIVE — the SAME machinery, with a cookie whose value IS a vuln-class signature. The
        // value is built to match ResponseAnalyzer's SQLI ErrorPattern Regex("Warning.*mysql_.*query")
        // (ResponseAnalyzer.kt:28), and `.` does not cross the newline that separates header lines,
        // so the greedy match is confined to the Set-Cookie line and spans exactly the cookie value.
        val hostileConfirmation =
            analyzer.analyze(
                original = responseWith(SET_COOKIE_BENIGN, "welcome back"),
                modified = responseWith(SET_COOKIE_SIGNATURE_SHAPED, "welcome back"),
                payload = payload,
                vulnClass = VulnClass.SQLI,
            )

        assertNotNull(
            hostileConfirmation,
            "the signature-shaped cookie value produced no confirmation; the reach measurement is " +
                "inconclusive rather than negative.",
        )
        assertTrue(
            hostileConfirmation.evidence.contains(SIGNATURE_COOKIE_VALUE),
            "expected the signature-shaped cookie value to appear verbatim in evidence, measured: " +
                "'${hostileConfirmation.evidence}'",
        )
        assertEquals(
            "PHP MySQL warning: 'Warning_mysql_fetch_query'",
            hostileConfirmation.evidence,
            "the positive fixture's evidence shape changed",
        )
    }

    /** One measured evidence-construction site: its 1-based source line and its truncation cap. */
    private data class EvidenceSite(
        val line: Int,
        val cap: Int,
    )

    /**
     * Walks [RESPONSE_ANALYZER_PATH], drops comment lines, and extracts every truncation applied
     * while building an evidence string.
     */
    private fun measureEvidenceConstructionSites(): List<EvidenceSite> =
        SourceRoots
            .file(RESPONSE_ANALYZER_PATH)
            .readLines()
            .mapIndexed { index, raw -> (index + 1) to raw }
            .filterNot { (_, raw) ->
                val trimmed = raw.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }.mapNotNull { (lineNumber, raw) ->
                EVIDENCE_CONSTRUCTION.find(raw)?.let { m ->
                    EvidenceSite(lineNumber, m.groupValues[1].toInt())
                }
            }

    /**
     * A deep-stub-free [HttpRequestResponse] carrying exactly one `Set-Cookie` header plus a body.
     *
     * `request().url()` is stubbed because `createConfirmation` (`ResponseAnalyzer.kt:1024`) wraps
     * the confirmation in an [ActiveScanTarget], whose `id` initializer reads it eagerly
     * (`ActiveScanModels.kt:300`). Nothing else on the Montoya surface is touched, which is why an
     * explicit three-mock fixture is used here instead of deep stubs — an unstubbed call would
     * throw rather than silently return a null that the assertion then mistakes for a clean result.
     */
    private fun responseWith(
        setCookieValue: String,
        body: String,
    ): HttpRequestResponse {
        val header = mock<HttpHeader>()
        whenever(header.name()).thenReturn("Set-Cookie")
        whenever(header.value()).thenReturn(setCookieValue)

        val response = mock<HttpResponse>()
        whenever(response.headers()).thenReturn(listOf(header))
        whenever(response.bodyToString()).thenReturn(body)

        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(FIXTURE_URL)

        val reqResp = mock<HttpRequestResponse>()
        whenever(reqResp.response()).thenReturn(response)
        whenever(reqResp.request()).thenReturn(request)
        return reqResp
    }

    private companion object {
        // Never appears in the matched-against text; it exists only so ActiveScanTarget.id can be
        // built. Deliberately free of the SQLI false-positive indicators ("example", ...).
        const val FIXTURE_URL = "https://app.test.invalid/login"
        const val RESPONSE_ANALYZER_PATH = "com/six2dez/burp/aiagent/scanner/ResponseAnalyzer.kt"

        /**
         * Every evidence string in this file is built by interpolating the pattern's label with a
         * truncated `match.value`. Matched as SOURCE TEXT on purpose: the caps are compile-time
         * literals inside a string template, so no runtime reflection can reach them.
         *
         * The narrower `match.value.take(N)` is the whole discriminator — measured 2026-08-27,
         * `take(` occurs in `ResponseAnalyzer.kt` at exactly the three evidence-construction sites
         * and nowhere else, so this pattern neither over- nor under-matches today. The site-count
         * assertion above is what turns a future divergence red.
         */
        val EVIDENCE_CONSTRUCTION = Regex("""match\.value\.take\((\d+)\)""")

        // MEASURED 2026-08-27 against ResponseAnalyzer.kt: :682 take(80), :720 take(60),
        // :791 take(80). Pinned as a drift tripwire, NOT as the source of truth — the walk above is.
        const val EXPECTED_SITE_COUNT = 3
        val EXPECTED_CAPS_SORTED = listOf(60, 80, 80)

        // Ordinary session-token shape. Deliberately free of any SQLI signature substring AND of the
        // SQLI false-positive indicators ("documentation", "example", "tutorial", ...) that would
        // short-circuit analyze() before any pattern ran.
        const val BENIGN_COOKIE_VALUE = "aK9xQ2mZ7pLf4vN8tR1bY6wE3hJ0uC5d"
        const val SET_COOKIE_BENIGN = "sid=$BENIGN_COOKIE_VALUE; Path=/; HttpOnly"

        // Built to satisfy Regex("Warning.*mysql_.*query", IGNORE_CASE) end-to-end, so the matched
        // span is exactly this string and the whole cookie value lands in evidence.
        const val SIGNATURE_COOKIE_VALUE = "Warning_mysql_fetch_query"
        const val SET_COOKIE_SIGNATURE_SHAPED = "sid=$SIGNATURE_COOKIE_VALUE; Path=/; HttpOnly"
    }
}
