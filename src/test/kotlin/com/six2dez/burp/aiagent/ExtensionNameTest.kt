package com.six2dez.burp.aiagent

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.StoreFlavorProfile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify

/**
 * An SPI with no provider anywhere on the classpath. Top-level and not private: ServiceLoader rejects a
 * service type its caller cannot access ("service type not accessible").
 */
internal interface ExtensionNameTestNoProviderSpi

/**
 * Phase 29 / BUILD-03 (D-04 amended, D-11 amended) — the store-classpath half of the extension-name pin.
 *
 * Both flavors must register under the byte-exact name "Custom AI Agent": Burp keys an extension's
 * preferences node by that name, so a different name in either build would open an empty node and the
 * settings and encrypted secrets of an existing install would become unreadable. FullExtensionNameTest
 * (src/fullTest) pins the same name on the full classpath. The class names differ on purpose: the
 * fullTest classpath also carries the test output, and two test classes with one FQN would collide.
 *
 * This suite reads App.kt from disk, which `tasks.test` covers through the
 * `mainSourceTreeStructuralInputs` input directory.
 */
class ExtensionNameTest {
    @Test
    fun storeClasspathResolvesTheCoreDefaultProfile() {
        val conflicts = mutableListOf<List<String>>()
        val profile = resolveFlavorProfile { conflicts += it }
        assertTrue(profile is StoreFlavorProfile, "store classpath must resolve StoreFlavorProfile, got ${profile.javaClass.name}")
        assertEquals("BApp Store build", profile.label)
        assertTrue(conflicts.isEmpty(), "no provider means no conflict, got $conflicts")
    }

    @Test
    fun registerExtensionIdentityCallsSetNameOnceWithTheExactName() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        registerExtensionIdentity(api, StoreFlavorProfile())
        verify(api.extension(), times(1)).setName("Custom AI Agent")
        val banner = argumentCaptor<String>()
        verify(api.logging(), times(1)).logToOutput(banner.capture())
        assertTrue(banner.firstValue.startsWith("Custom AI Agent "), "banner: ${banner.firstValue}")
        assertTrue(banner.firstValue.contains("BApp Store build"), "banner: ${banner.firstValue}")
    }

    @Test
    fun extensionNameIsByteExact() {
        assertEquals("Custom AI Agent", EXTENSION_NAME)
        assertEquals(15, EXTENSION_NAME.length)
        assertEquals(EXTENSION_NAME.trim(), EXTENSION_NAME)
        assertTrue(EXTENSION_NAME.all { it.code in 0x20..0x7E }, "name must be printable ASCII")
    }

    @Test
    fun appKtNamesTheExtensionInExactlyOnePlace() {
        // SourceRoots.file fails naming both production roots when App.kt is in neither or in both.
        val source = SourceRoots.file("com/six2dez/burp/aiagent/App.kt").readText()

        val occurrences = Regex("""setName\(""").findAll(source).map { it.range.first }.toList()
        assertEquals(1, occurrences.size, "App.kt must call setName( exactly once, found ${occurrences.size}")

        val identityStart = source.indexOf("fun registerExtensionIdentity(")
        assertTrue(identityStart >= 0, "registerExtensionIdentity not found in App.kt")
        val identityEnd = source.indexOf("\n}", identityStart)
        assertTrue(
            occurrences.single() in identityStart..identityEnd,
            "the only setName( call must sit inside registerExtensionIdentity",
        )

        val initStart = source.indexOf("fun initialize(")
        assertTrue(initStart >= 0, "initialize not found in App.kt")
        val initEnd = source.indexOf("\n    fun shutdown(", initStart)
        assertTrue(initEnd > initStart, "shutdown() not found after initialize in App.kt")
        assertTrue(
            source.substring(initStart, initEnd).contains("registerExtensionIdentity("),
            "initialize must name the extension through registerExtensionIdentity",
        )
    }

    @Test
    fun pluginsSingleWithNoProviderReturnsNullWithoutConflict() {
        var conflictCalled = false
        val result = Plugins.single(ExtensionNameTestNoProviderSpi::class.java) { conflictCalled = true }
        assertNull(result)
        assertFalse(conflictCalled, "onConflict must not run when there are no providers")
        assertTrue(Plugins.load(ExtensionNameTestNoProviderSpi::class.java).isEmpty())
    }
}
