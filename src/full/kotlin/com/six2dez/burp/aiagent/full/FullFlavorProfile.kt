package com.six2dez.burp.aiagent.full

import com.six2dez.burp.aiagent.spi.FlavorProfile

/**
 * Phase 29 — the full (GitHub) build's [FlavorProfile], registered through
 * `META-INF/services/com.six2dez.burp.aiagent.spi.FlavorProfile`, a file only the full JAR carries.
 *
 * A class rather than an `object`: ServiceLoader needs a public no-arg constructor.
 */
class FullFlavorProfile : FlavorProfile {
    override val label: String = "GitHub full build"
}
