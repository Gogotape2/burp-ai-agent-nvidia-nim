package com.six2dez.burp.aiagent.spi

/**
 * Phase 29 / D-04 (amended) — describes which build is running, for display only.
 *
 * [label] feeds the one load banner the extension writes to Burp's Output tab. It never selects
 * behavior (flavor behavior comes from which providers are on the classpath, BUILD-04) and it never
 * feeds the Burp extension name: both flavors register under the same name, so they share one
 * preferences node and the settings and encrypted secrets of an existing install stay readable.
 *
 * The full flavor supplies its own implementation through `META-INF/services`; the store flavor has
 * none and resolves [StoreFlavorProfile].
 */
interface FlavorProfile {
    val label: String
}

/** The core default: what the BApp Store JAR resolves, because it carries no FlavorProfile provider. */
class StoreFlavorProfile : FlavorProfile {
    override val label: String = "BApp Store build"
}
