package com.six2dez.burp.aiagent.config

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * WR-01 (25-REVIEW): the MCP bearer token is the key of the bind-conflict takeover proof's HMAC, and
 * every byte of that HMAC's message is known to a squatter. A captured proof is therefore an OFFLINE
 * verifier for the token — one HMAC-SHA256 per guess, no victim interaction, no rate limit. Before
 * this floor existed the only validation anywhere on the token field was `isBlank()`.
 *
 * The predicate under test is deliberately pure and AWT-free so it can be asserted here; the notice
 * that makes it visible to the operator lives in `SettingsPanelMcpTabs.refreshMcpNotice`, which
 * cannot be constructed headlessly and is therefore asserted structurally at the bottom of this file.
 */
class McpTokenStrengthTest {
    @Test
    fun blankToken_isWeak() {
        assertTrue(McpSettings.isTokenWeak(""), "an empty token must be weak")
        assertTrue(McpSettings.isTokenWeak("   \t \n "), "a whitespace-only token must be weak")
    }

    @Test
    fun tokenOneCharacterBelowTheFloor_isWeak() {
        val justShort = "a".repeat(Defaults.MCP_MIN_TOKEN_LENGTH - 1)
        assertTrue(
            McpSettings.isTokenWeak(justShort),
            "a token of ${justShort.length} characters must be weak against a floor of " +
                "${Defaults.MCP_MIN_TOKEN_LENGTH}",
        )
    }

    @Test
    fun tokenAtAndAboveTheFloor_isNotWeak() {
        val exactly = "a".repeat(Defaults.MCP_MIN_TOKEN_LENGTH)
        val longer = "a".repeat(Defaults.MCP_MIN_TOKEN_LENGTH + 8)
        assertFalse(McpSettings.isTokenWeak(exactly), "the floor is inclusive: exactly N is not weak")
        assertFalse(McpSettings.isTokenWeak(longer), "a token longer than the floor is not weak")
    }

    @Test
    fun paddingDoesNotBuyLength_tokenIsTrimmedBeforeMeasuring() {
        val padded = "  " + "a".repeat(Defaults.MCP_MIN_TOKEN_LENGTH - 1) + "  "
        assertTrue(padded.length > Defaults.MCP_MIN_TOKEN_LENGTH, "fixture must be long enough untrimmed")
        assertTrue(
            McpSettings.isTokenWeak(padded),
            "surrounding whitespace must not count toward the floor — the server trims before comparing",
        )
    }

    /**
     * T-26-03-05: a floor that fires against the product's OWN default token trains the operator to
     * dismiss the notice, at which point the control has stopped being one. Sampled rather than
     * asserted once, because `generateToken` is randomised and a length that varied would be exactly
     * the way this fails intermittently in the field rather than here.
     */
    @Test
    fun generatedTokenIsNeverWeak() {
        repeat(GENERATED_TOKEN_SAMPLES) { index ->
            val token = McpSettings.generateToken()
            assertFalse(
                McpSettings.isTokenWeak(token),
                "generateToken() sample #$index produced '${token.length}' characters, which the " +
                    "floor of ${Defaults.MCP_MIN_TOKEN_LENGTH} classifies as weak. The advisory must " +
                    "never fire against the value the product itself generates.",
            )
        }
    }

    /**
     * The relation, not the two constants independently: raising [Defaults.MCP_MIN_TOKEN_LENGTH]
     * without also lengthening [McpSettings.generateToken] fails HERE, which is what makes the
     * prohibition machine-checked instead of a sentence in a plan.
     */
    @Test
    fun theFloorNeverExceedsTheGeneratedTokenLength() {
        val generatedLength = McpSettings.generateToken().length
        assertTrue(
            Defaults.MCP_MIN_TOKEN_LENGTH <= generatedLength,
            "MCP_MIN_TOKEN_LENGTH is ${Defaults.MCP_MIN_TOKEN_LENGTH} but generateToken() yields " +
                "$generatedLength characters. The floor must never exceed the product's own default.",
        )
    }

    /**
     * Structural, and only structural: the MCP notice is composed by `SettingsPanel` extensions and
     * `SettingsPanel` cannot be constructed under `-Djava.awt.headless=true`, so the wiring is
     * asserted by reading the declaring source the same way `ChatPanelToolGateTest` does for its
     * modal-dialog path. `build.gradle.kts` already declares `src/main/kotlin` as a `tasks.test`
     * input tree, so an edit here invalidates the cache and this really re-runs.
     *
     * Both links of the chain are asserted, because either one alone can rot silently: the item
     * builder can grow the weak-token bullet while `refreshMcpNotice` stops calling it, or the call
     * can survive while the bullet is deleted.
     */
    @Test
    fun theNoticeConsumesThePredicateAndRaisesARiskItem() {
        val builder = functionBody("private fun SettingsPanel.mcpNoticeItems()")

        assertTrue(
            builder.contains("isTokenWeak"),
            "mcpNoticeItems does not call isTokenWeak — the predicate exists but the operator is " +
                "never told, which leaves WR-01's mitigation advisory in name only.",
        )
        assertTrue(
            builder.contains("SubtleNotice.Level.RISK"),
            "the weak-token case must be surfaced as a RISK item",
        )

        val renderer = functionBody("internal fun SettingsPanel.refreshMcpNotice()")
        assertTrue(
            renderer.contains("mcpNoticeItems()"),
            "refreshMcpNotice must consume mcpNoticeItems(), or the bullets are composed and dropped",
        )
    }

    private companion object {
        const val GENERATED_TOKEN_SAMPLES = 50

        const val MCP_TABS_SOURCE = "com/six2dez/burp/aiagent/ui/SettingsPanelMcpTabs.kt"

        /** Brace-matched body of [declaration], mirroring `ChatPanelToolGateTest.functionBody`. */
        fun functionBody(declaration: String): String {
            // SourceRoots.file fails naming both production roots when the file is in neither or in both.
            val source = SourceRoots.file(MCP_TABS_SOURCE).readText()
            val start = source.indexOf(declaration)
            require(start >= 0) { "No '$declaration' in $MCP_TABS_SOURCE — this assertion is stale." }
            val open = source.indexOf('{', start)
            var depth = 0
            var index = open
            while (index < source.length) {
                if (source[index] == '{') depth++
                if (source[index] == '}') {
                    depth--
                    if (depth == 0) break
                }
                index++
            }
            return source.substring(open, index + 1)
        }
    }
}
