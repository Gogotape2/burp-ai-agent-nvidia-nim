package com.six2dez.burp.aiagent.spi

import java.util.ServiceLoader

/**
 * Phase 29 / BUILD-01 — the one seam through which the full flavor plugs code into the core.
 *
 * The core (`src/main`, the only input of the BApp Store JAR) declares an SPI interface and a store
 * default. The full flavor (`src/full`) ships a provider class plus a
 * `META-INF/services/<interface FQN>` line, and only the full JAR carries that file. The store JAR
 * therefore finds no provider and the caller falls back to its core default.
 *
 * ServiceLoader is given the SPI type's own classloader on purpose, as in `BackendRegistry.reload`:
 * Burp loads each extension under its own classloader, and the thread context classloader may not see
 * this JAR's `META-INF/services`, in which case every lookup would silently return nothing.
 *
 * Providers MUST be classes with a public no-arg constructor. A Kotlin `object` has a private
 * constructor, so ServiceLoader cannot instantiate it and throws `ServiceConfigurationError`.
 */
object Plugins {
    /**
     * Every provider of [type] visible to [type]'s classloader, ordered by implementation class name
     * so the result does not depend on classpath or JAR entry order.
     */
    fun <T : Any> load(type: Class<T>): List<T> =
        ServiceLoader
            .load(type, type.classLoader)
            .toList()
            .sortedBy { it.javaClass.name }

    /**
     * The single provider of [type], or null.
     *
     * - no provider: null (the store flavor, or an SPI the running flavor does not implement);
     * - exactly one: that provider;
     * - more than one: null after [onConflict] receives the provider class names. Picking one at
     *   random would make behavior depend on JAR order, so callers fall back to the core default and
     *   the conflict is reported instead.
     */
    fun <T : Any> single(
        type: Class<T>,
        onConflict: (List<String>) -> Unit = {},
    ): T? {
        val providers = load(type)
        return when (providers.size) {
            0 -> null
            1 -> providers.first()
            else -> {
                onConflict(providers.map { it.javaClass.name })
                null
            }
        }
    }
}
