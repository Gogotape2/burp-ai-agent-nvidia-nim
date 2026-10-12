package com.six2dez.burp.aiagent.full

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.buildIdentityLine
import com.six2dez.burp.aiagent.registerExtensionIdentity
import com.six2dez.burp.aiagent.resolveFlavorProfile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify

/**
 * Phase 29 / UI-SPEC PC-15 (S25, C-N12) — the full-classpath half of the Help build caption pin.
 *
 * The identity line of the resolved profile is the logged banner and ends with the full profile's
 * label. It is label-agnostic on purpose: plan 29-17 relabels the full build (PC-14) and pins the
 * literal. The class name differs from the store HelpBuildCaptionTest so the FQNs do not collide on
 * this classpath, which also carries the store test output.
 */
class FullHelpBuildCaptionTest {
    @Test
    fun theFullIdentityLineIsTheLoggedBannerAndEndsWithTheFullLabel() {
        val profile = resolveFlavorProfile()
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        registerExtensionIdentity(api, profile)
        val banner = argumentCaptor<String>()
        verify(api.logging(), times(1)).logToOutput(banner.capture())

        val line = buildIdentityLine(profile)
        assertEquals(banner.firstValue, line, "C-N12: the caption and the S3 banner are one string.")
        assertTrue(
            line.endsWith("(" + FullFlavorProfile().label + ")"),
            "S25: the full label closes the line. Line: $line",
        )
    }
}
