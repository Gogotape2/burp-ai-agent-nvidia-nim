package com.six2dez.burp.aiagent.full

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.EXTENSION_NAME
import com.six2dez.burp.aiagent.registerExtensionIdentity
import com.six2dez.burp.aiagent.resolveFlavorProfile
import com.six2dez.burp.aiagent.spi.FlavorProfile
import com.six2dez.burp.aiagent.spi.Plugins
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify

/**
 * Phase 29 / BUILD-03 (D-04 amended, D-11 amended) — the full-classpath half of the extension-name pin.
 *
 * On the full classpath the FlavorProfile services file from src/full is visible, so the seam must
 * resolve [FullFlavorProfile], and the extension must still register under the same byte-exact name
 * as the store build: one name, one Burp preferences node, so the settings and encrypted secrets of an
 * existing install stay readable after the upgrade.
 */
class FullExtensionNameTest {
    @Test
    fun fullClasspathResolvesTheFullProfileThroughServiceLoader() {
        val conflicts = mutableListOf<List<String>>()
        val profile = resolveFlavorProfile { conflicts += it }
        assertTrue(profile is FullFlavorProfile, "full classpath must resolve FullFlavorProfile, got ${profile.javaClass.name}")
        assertTrue(conflicts.isEmpty(), "exactly one provider expected, got conflicts $conflicts")
        assertEquals(
            listOf(FullFlavorProfile::class.java.name),
            Plugins.load(FlavorProfile::class.java).map { it.javaClass.name },
        )
    }

    @Test
    fun fullBuildRegistersTheSameExtensionNameAndLabelsItsBanner() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        registerExtensionIdentity(api, resolveFlavorProfile())
        verify(api.extension(), times(1)).setName("Custom AI Agent")
        assertEquals("Custom AI Agent", EXTENSION_NAME)
        val banner = argumentCaptor<String>()
        verify(api.logging(), times(1)).logToOutput(banner.capture())
        assertTrue(banner.firstValue.contains("full build"), "banner: ${banner.firstValue}")
    }
}
