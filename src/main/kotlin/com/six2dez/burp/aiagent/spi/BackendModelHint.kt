package com.six2dez.burp.aiagent.spi

/**
 * Phase 29 / D-06 — lets a plug-in suggest the model a core backend should use when the user left
 * that backend's model field blank.
 *
 * The core supervisor loads providers once with `Plugins.load(BackendModelHint::class.java)` and asks
 * them in order; the first non-blank answer wins, and with none the backend keeps its core default.
 * The store build ships no provider, so its blank Ollama model always falls back to the core default.
 * The full build's CLI plug-in answers for `ollama` with the model named in the Ollama CLI command,
 * which it owns (user decision 2026-10-09).
 *
 * Providers MUST be classes with a public no-arg constructor (see [Plugins]). [defaultModel] runs on
 * the thread that builds the launch configuration and must not block or touch Swing.
 */
interface BackendModelHint {
    /** The model to use for [backendId], or null when this plug-in has no suggestion. */
    fun defaultModel(
        backendId: String,
        store: PluginSettingsStore,
    ): String?
}
