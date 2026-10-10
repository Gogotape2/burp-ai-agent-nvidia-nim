package com.six2dez.burp.aiagent.spi

import com.six2dez.burp.aiagent.resolveAiAccessPolicy
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 29 / BUILD-04 (T-29-14) — the provider selection boundary every flavor policy relies on:
 * 0 providers -> no provider (the caller uses its strict core default), 1 -> that provider, 2 or more
 * -> no provider plus a conflict report naming every provider class. The probes are test-only SPIs
 * (PluginsProbeServices.kt), so these cases never depend on what the production JARs register.
 */
class PluginsSelectionTest {
    @Test
    fun noProviderSelectsNothingAndReportsNoConflict() {
        val conflicts = mutableListOf<List<String>>()
        assertNull(Plugins.single(UnregisteredProbe::class.java) { conflicts += it })
        assertTrue(conflicts.isEmpty(), "onConflict must not be called without providers: $conflicts")
    }

    @Test
    fun exactlyOneProviderIsSelected() {
        val conflicts = mutableListOf<List<String>>()
        val selected = Plugins.single(SingleProbe::class.java) { conflicts += it }
        assertTrue(selected is SingleProbeImpl, "expected SingleProbeImpl, got ${selected?.javaClass?.name}")
        assertTrue(conflicts.isEmpty(), "onConflict must not be called for one provider: $conflicts")
    }

    @Test
    fun twoProvidersSelectNothingAndReportBothClassNamesSorted() {
        val conflicts = mutableListOf<List<String>>()
        assertNull(Plugins.single(DoubleProbe::class.java) { conflicts += it })
        assertEquals(
            listOf(listOf(DoubleProbeAlpha::class.java.name, DoubleProbeBeta::class.java.name)),
            conflicts,
            "onConflict must be called once with every provider class name, sorted",
        )
    }

    @Test
    fun storeClasspathResolvesTheStrictStorePolicy() {
        val conflicts = mutableListOf<List<String>>()
        val policy = resolveAiAccessPolicy { conflicts += it }
        assertTrue(policy is StoreAiAccessPolicy, "store classpath must resolve StoreAiAccessPolicy, got ${policy.javaClass.name}")
        assertTrue(conflicts.isEmpty(), "the store classpath registers no AiAccessPolicy provider: $conflicts")
        assertTrue(Plugins.load(AiAccessPolicy::class.java).isEmpty(), "no AiAccessPolicy provider may exist on the store classpath")
    }
}
