package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.spi.SuggestedTargetSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.verifyNoInteractions
import java.util.Collections

/**
 * Quick 261009-d0i - short acronyms in a passive finding title match only as whole words ("ato" no
 * longer matches "Indicators", "rce" no longer matches "Source") and NoSQL is checked before SQL. The
 * class picked by `mapTitleToVulnClass` drives both the `[AI Passive]` issue name and the suggested
 * targets the passive scanner offers to its [SuggestedTargetSink], so both are checked through the
 * real code paths.
 *
 * Phase 29 / D-02: the passive scanner holds no active-scanner reference. It builds suggested targets
 * only when a sink is installed (the full build's opt-in auto-queue plug-in) and offers them once; the
 * sink, not the core, decides whether anything is queued.
 */
class PassiveTitleClassifierTest {
    @Test
    fun shortTokensInsideOtherWordsNoLongerPickAClass() {
        PassiveScanCheckRig().use { rig ->
            assertEquals(emptyList<String>(), mismatches(rig, REGRESSION_ROWS))
        }
    }

    @Test
    fun titlesClassifiedCorrectlyTodayKeepTheirClass() {
        PassiveScanCheckRig().use { rig ->
            assertEquals(emptyList<String>(), mismatches(rig, KEEP_ROWS))
        }
    }

    @Test
    fun theFourLocalHeuristicTitlesMapToTheirOwnClass() {
        PassiveScanCheckRig().use { rig ->
            val smuggling = rig.pageGet("title-local-smuggling.example", smugglingIndicators = true)
            val csrf = rig.csrfPost("title-local-csrf.example")
            val smugglingTitle =
                rig.scanner
                    .localChecks(smuggling.request(), smuggling.response())
                    .single()
                    .title
            val csrfTitle =
                rig.scanner
                    .localChecks(csrf.request(), csrf.response())
                    .single()
                    .title
            val rows =
                listOf(
                    smugglingTitle to VulnClass.REQUEST_SMUGGLING,
                    csrfTitle to VulnClass.CSRF,
                    // Literal titles from PassiveAiScannerHeuristics.kt: the rig has no builder for these requests.
                    "Deserialization Surface Detected" to VulnClass.DESERIALIZATION,
                    "Unrestricted File Upload (Executable Extension)" to VulnClass.UNRESTRICTED_FILE_UPLOAD,
                )

            assertEquals(emptyList<String>(), mismatches(rig, rows))
        }
    }

    @Test
    fun theSmugglingFindingIsFiledUnderRequestSmuggling() {
        PassiveScanCheckRig().use { rig ->
            rig.scanner.setEnabled(true)

            rig.check.doCheck(rig.pageGet("title-smuggling.example", smugglingIndicators = true))
            rig.drain()

            assertEquals(listOf("[AI Passive] REQUEST_SMUGGLING"), rig.built.map { it.name })
            assertEquals("[AI Passive] SOURCEMAP_DISCLOSURE", rig.scanner.issueNameForPassive("JavaScript Source Map Exposed"))
            assertEquals("[AI Passive] NOSQL_INJECTION", rig.scanner.issueNameForPassive("NoSQL Injection"))
        }
    }

    @Test
    fun aSqlInjectionFindingOffersSqliTargetsToTheSink() {
        PassiveScanCheckRig(offerSettings(ScanMode.FULL)).use { rig ->
            val sink = RecordingSink()
            rig.scanner.suggestedTargetSink = sink
            val request = rig.csrfPost("offer-sqli.example")

            rig.scanner.offerSuggestedTargets(request, "SQL Injection", "Medium", "evidence", 90, rig.settings)

            val offered = sink.offers.single()
            assertTrue(offered.targets.isNotEmpty(), "the request's injection points become targets")
            assertEquals(setOf(VulnClass.SQLI), offered.classes())
            assertEquals(setOf(MEDIUM_PRIORITY), offered.priorities())
            assertEquals(setOf(90), offered.targets.map { it.vulnHint.confidence }.toSet())
            assertTrue(offered.targets.all { it.originalRequest === request }, "every target keeps the original request")
            assertSame(rig.settings, offered.settings, "the sink receives the settings the scan ran with")
        }
    }

    @Test
    fun theTargetPriorityFollowsTheFindingSeverity() {
        PassiveScanCheckRig(offerSettings(ScanMode.FULL)).use { rig ->
            val sink = RecordingSink()
            rig.scanner.suggestedTargetSink = sink
            val expected =
                listOf(
                    "CRITICAL" to 100,
                    "High" to 80,
                    "medium" to MEDIUM_PRIORITY,
                    "Low" to 40,
                    "Information" to 40,
                )

            expected.forEachIndexed { index, (severity, _) ->
                rig.scanner.offerSuggestedTargets(
                    rig.csrfPost("offer-priority-$index.example"),
                    "SQL Injection",
                    severity,
                    "evidence",
                    90,
                    rig.settings,
                )
            }

            val actual = sink.offers.map { it.priorities() }
            assertEquals(expected.map { (_, priority) -> setOf(priority) }, actual, "priorities for ${expected.map { it.first }}")
        }
    }

    @Test
    fun withNoSinkNothingIsBuiltOrOffered() {
        PassiveScanCheckRig(offerSettings(ScanMode.FULL)).use { rig ->
            val request = mock<HttpRequestResponse>()

            rig.scanner.offerSuggestedTargets(request, "SQL Injection", "High", "evidence", 90, rig.settings)

            // extractInjectionPoints reads the request: an untouched request means no target was built.
            verifyNoInteractions(request)
            assertNull(rig.scanner.suggestedTargetSink, "the store classpath installs no sink")
        }
    }

    @Test
    fun passiveOnlyAndModeDisallowedClassesAreNeverOffered() {
        PassiveScanCheckRig(offerSettings(ScanMode.BUG_BOUNTY)).use { rig ->
            val sink = RecordingSink()
            rig.scanner.suggestedTargetSink = sink
            val neverOffered =
                listOf(
                    // ScanPolicy.PASSIVE_ONLY_VULN_CLASSES
                    "HTTP Request Smuggling Indicators" to "offer-smuggling.example",
                    "JavaScript Source Map Exposed" to "offer-sourcemap.example",
                    "Anti-CSRF Token Missing" to "offer-csrf.example",
                    // no class at all
                    "Missing Brute Force Protection" to "offer-bruteforce.example",
                    // real classes that BUG_BOUNTY mode does not test
                    "LDAP Injection" to "offer-ldap.example",
                    "LFI via Path Parameter" to "offer-lfi.example",
                )

            for ((title, host) in neverOffered) {
                rig.scanner.offerSuggestedTargets(rig.csrfPost(host), title, "High", "evidence", 90, rig.settings)
            }
            assertEquals(emptyList<Offer>(), sink.offers)

            rig.scanner.offerSuggestedTargets(rig.csrfPost("offer-bb-sqli.example"), "SQL Injection", "High", "evidence", 90, rig.settings)
            assertEquals(setOf(VulnClass.SQLI), sink.offers.single().classes())
        }
    }

    @Test
    fun theCoreOffersEvenWhenTheActiveScannerIsOffBecauseTheSinkDecides() {
        PassiveScanCheckRig(offerSettings(ScanMode.FULL).copy(activeAiEnabled = false)).use { rig ->
            val sink = RecordingSink()
            rig.scanner.suggestedTargetSink = sink

            rig.scanner.offerSuggestedTargets(rig.csrfPost("offer-gate.example"), "SQL Injection", "High", "evidence", 90, rig.settings)

            assertEquals(1, sink.offers.size, "core has no settings gate; the sink applies its own")
        }
    }

    @Test
    fun aRecordedIssueOffersItsSuggestedTargetsOnce() {
        PassiveScanCheckRig(offerSettings(ScanMode.FULL)).use { rig ->
            val sink = RecordingSink()
            rig.scanner.suggestedTargetSink = sink

            rig.scanner.recordNewIssue(rig.csrfPost("offer-record.example"), "SQL Injection", "High", "detail", 90, rig.settings, "test")

            assertEquals(setOf(VulnClass.SQLI), sink.offers.single().classes())
        }
    }

    private data class Offer(
        val targets: List<ActiveScanTarget>,
        val settings: AgentSettings,
    ) {
        fun classes(): Set<VulnClass> = targets.map { it.vulnHint.vulnClass }.toSet()

        fun priorities(): Set<Int> = targets.map { it.priority }.toSet()
    }

    private class RecordingSink : SuggestedTargetSink {
        val offers: MutableList<Offer> = Collections.synchronizedList(mutableListOf())

        override fun offer(
            targets: List<ActiveScanTarget>,
            settings: AgentSettings,
        ) {
            offers += Offer(targets, settings)
        }
    }

    private fun offerSettings(mode: ScanMode): AgentSettings =
        TestSettings.baselineSettings().copy(
            passiveAiEnabled = true,
            passiveAiScopeOnly = false,
            activeAiEnabled = true,
            activeAiScanMode = mode,
        )

    private fun mismatches(
        rig: PassiveScanCheckRig,
        rows: List<Pair<String, VulnClass?>>,
    ): List<String> =
        rows.mapNotNull { (title, expected) ->
            val actual = rig.scanner.mapTitleToVulnClass(title)
            if (actual == expected) null else "$title -> $actual (expected $expected)"
        }

    private companion object {
        const val MEDIUM_PRIORITY = 60

        /** Titles where a short token sat inside another word, or NoSQL lost to SQL. */
        val REGRESSION_ROWS: List<Pair<String, VulnClass?>> =
            listOf(
                "Input Validator Bypass" to null,
                "Open Redirect via Locator Parameter" to VulnClass.OPEN_REDIRECT,
                "Authenticator Misconfiguration" to null,
                "Moderator Panel Exposed" to null,
                "Template Generator Disclosure" to null,
                "Spring Boot Actuator Exposed" to VulnClass.DEBUG_EXPOSURE,
                "JavaScript Source Map Exposed" to VulnClass.SOURCEMAP_DISCLOSURE,
                "Exposed Source Code" to null,
                "Insecure Resource Sharing" to null,
                "Cross-Origin Resource Sharing (CORS) Misconfiguration" to VulnClass.CORS_MISCONFIGURATION,
                "Missing Brute Force Protection" to null,
                "Weak Password Policy Enforcement" to null,
                "Ecommerce Cart Tampering" to null,
                "NoSQL Injection" to VulnClass.NOSQL_INJECTION,
                "MongoDB NoSQL Operator Injection" to VulnClass.NOSQL_INJECTION,
                "NoSQL Injection in Database Query" to VulnClass.NOSQL_INJECTION,
                "Associated Session Bypass" to null,
                "Corridor Access" to null,
            )

        /** Titles classified correctly before the fix; they guard plurals, `_` boundaries, SQLi, dialects and long words. */
        val KEEP_ROWS: List<Pair<String, VulnClass?>> =
            listOf(
                "Remote Code Execution (RCE)" to VulnClass.CMDI,
                "OS Command Injection" to VulnClass.CMDI,
                "Pre-auth RCE" to VulnClass.CMDI,
                "Account Takeover via Password Reset" to VulnClass.ACCOUNT_TAKEOVER,
                "ATO via Email Change" to VulnClass.ACCOUNT_TAKEOVER,
                "Single Sign-On (SSO) Bypass" to VulnClass.OAUTH_MISCONFIGURATION,
                "AWS S3 Bucket Exposed" to VulnClass.S3_MISCONFIGURATION,
                "Price Manipulation" to VulnClass.PRICE_MANIPULATION,
                "Self-Inflicted XSS" to VulnClass.XSS_REFLECTED,
                "Stored-XSS in Comments" to VulnClass.XSS_REFLECTED,
                "SQL Injection" to VulnClass.SQLI,
                "Time-based SQL-Injection" to VulnClass.SQLI,
                "Blind SQLi in Search Parameter" to VulnClass.SQLI,
                "Verbose Error Message (MySQL)" to VulnClass.SQLI,
                "PostgreSQL Error Disclosure" to VulnClass.SQLI,
                "MSSQL Error Message" to VulnClass.SQLI,
                "SQLite Error Disclosure" to VulnClass.SQLI,
                "LFI via Path Parameter" to VulnClass.LFI,
                "SSTI in Jinja2 Template" to VulnClass.SSTI,
                "Blind SSRF via Webhook" to VulnClass.SSRF,
                "XXE Injection" to VulnClass.XXE,
                "LDAP Injection" to VulnClass.LDAP_INJECTION,
                "BOLA on Orders API" to VulnClass.BOLA,
                "IDORs on Order Endpoints" to VulnClass.IDOR,
                "BFLA on Admin Endpoint" to VulnClass.BFLA,
                "2FA Bypass" to VulnClass.MFA_BYPASS,
                "MFA Bypass" to VulnClass.MFA_BYPASS,
                "JWTs Signed With None Algorithm" to VulnClass.JWT_WEAKNESS,
                "jwt_secret Exposed" to VulnClass.JWT_WEAKNESS,
                "Anti-CSRF Token Missing" to VulnClass.CSRF,
                "CRLF Injection" to VulnClass.HEADER_INJECTION,
                "CORS Misconfiguration" to VulnClass.CORS_MISCONFIGURATION,
                "TOCTOU Race in Checkout" to VulnClass.RACE_CONDITION_TOCTOU,
                "Debugging Enabled" to VulnClass.DEBUG_EXPOSURE,
                "Exposed .git Directory" to VulnClass.GIT_EXPOSURE,
                "Missing HSTS Header" to null,
                "Session Fixation" to null,
            )
    }
}
