package com.six2dez.burp.aiagent.spi

import com.six2dez.burp.aiagent.backends.AiBackend

/**
 * Phase 31 / D-14 (WR-05, ADR-18 OQ8) — backends loaded from outside the extension JAR.
 *
 * `BackendRegistry.reload` asks every provider of this interface, after the built-in backends and
 * Burp AI, for the backends to register on that reload. The full build registers the drop-in loader
 * (src/full) through its `META-INF/services` file. The BApp Store JAR registers no provider, so the
 * store build never creates, lists or loads a drop-in directory and runs no code from outside its own
 * reviewed JAR.
 *
 * Providers MUST be classes with a public no-arg constructor (see [Plugins]).
 */
interface ExternalBackendSource {
    /**
     * The backends to register on this reload. [parent] is the extension's class loader; [log] writes
     * one line to Burp's Output tab and [logError] one line to its error output.
     */
    fun load(
        parent: ClassLoader,
        log: (String) -> Unit,
        logError: (String) -> Unit,
    ): List<AiBackend>

    /**
     * Releases what the previous [load] opened (class loaders). Called before each [load] and on
     * extension unload. A provider must not throw from here: it logs a failure and returns.
     */
    fun close()
}
