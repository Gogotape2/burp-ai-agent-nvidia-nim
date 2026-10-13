package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.BuildFlags
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * SEC-05 5a: the MCP server used to advertise a hardcoded `Implementation("burp-ai-agent", "0.6.0")`
 * while the project moved on to a newer release. `BuildFlags.VERSION` is now generated from
 * `build.gradle.kts`'s single `version = "..."` declaration, so this test guards the seam rather
 * than the literal value.
 *
 * Naming note: the class name contains `BuildFlags` on purpose — the phase gate runs it via
 * `--tests '*BuildFlags*'`. It deliberately does NOT end in `IntegrationTest` (or any other suffix
 * listed in the `excludeHeavyTests` filter block inside `tasks.test` in `build.gradle.kts`), because
 * `-PexcludeHeavyTests=true` would silently skip it. Anchored on the symbol rather than a line
 * range: the previous `build.gradle.kts:145-157` citation went stale and cost real time twice.
 */
class McpBuildFlagsVersionTest {
    @Test
    fun version_isARealSemverAndNotTheHardcodedPlaceholder() {
        val semver = Regex("""^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$""")
        assertTrue(
            semver.matches(BuildFlags.VERSION),
            "BuildFlags.VERSION must be a semver string, was '${BuildFlags.VERSION}'",
        )
        // Deliberately not asserting a literal release number: that would couple every version bump
        // to a test edit. Only the stale hardcoded value is forbidden.
        assertNotEquals(
            "0.6.0",
            BuildFlags.VERSION,
            "BuildFlags.VERSION is still the stale hardcoded MCP placeholder",
        )
    }
}
