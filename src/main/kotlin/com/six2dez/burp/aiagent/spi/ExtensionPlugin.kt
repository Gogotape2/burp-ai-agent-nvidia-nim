package com.six2dez.burp.aiagent.spi

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner

/**
 * Phase 29 / D-02, BUILD-04 — what an [ExtensionPlugin] is handed when the extension loads.
 *
 * @property api the extension's Montoya API.
 * @property pluginSettings the plug-in settings store (`AgentSettingsRepository.pluginSettings()`).
 * @property passiveScanner the extension's one passive AI scanner.
 * @property activeScanner the extension's one active AI scanner.
 * @property log writes one line to Burp's Output tab.
 */
class PluginHost(
    val api: MontoyaApi,
    val pluginSettings: PluginSettingsStore,
    val passiveScanner: PassiveAiScanner,
    val activeScanner: ActiveAiScanner,
    val log: (String) -> Unit,
)

/**
 * Phase 29 / D-02, BUILD-04 — a full-build plug-in with a load / unload lifecycle.
 *
 * `App.initialize` loads every provider with `Plugins.load(ExtensionPlugin::class.java)` after both
 * scanners exist and calls [install] on each; a provider whose [install] throws is logged and skipped,
 * and the extension still loads. `App.shutdown` calls [shutdown] on each installed plug-in right after
 * the main tab is torn down and before the scanners shut down.
 *
 * The store build ships no `META-INF/services` file for this interface, so it installs nothing.
 * Providers MUST be classes with a public no-arg constructor (see [Plugins]).
 */
interface ExtensionPlugin {
    fun install(host: PluginHost)

    fun shutdown() {}
}
