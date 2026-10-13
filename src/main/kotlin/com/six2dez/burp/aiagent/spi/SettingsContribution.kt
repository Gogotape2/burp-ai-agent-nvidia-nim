package com.six2dez.burp.aiagent.spi

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.config.AgentSettings
import javax.swing.JComponent

/**
 * Phase 29 / D-07 — where a [SettingsContribution]'s component is placed in the settings window.
 *
 * - [BACKEND_CARD]: under the backend card named by [SettingsContribution.backendId]. An id with a
 *   core card (for example `ollama`) gets the component appended below that card's last row; an id
 *   with no core card gets a new card registered under that id.
 * - [MCP_TAB]: appended to the MCP Server tab's section stack, after the core sections, with no gap
 *   added by the host.
 * - [ACTIVE_SCANNER_TAB]: inside the AI Active Scanner body, after "Scan parameters", each preceded by
 *   the `DesignTokens.Spacing.sm` gap the core accordions already use.
 *
 * The host adds no other spacing: a contribution owns its own padding.
 */
enum class SettingsSlot { BACKEND_CARD, MCP_TAB, ACTIVE_SCANNER_TAB }

/**
 * Marker for the value a [SettingsContribution] reads off its own Swing components. Each contribution
 * defines its own immutable data class and casts back to it in [SettingsContribution.persist] and
 * [SettingsContribution.applyToUi]; the host never looks inside.
 */
interface ContributionSnapshot

/**
 * What the host hands a contribution when its component is built.
 *
 * @property api the extension's Montoya API.
 * @property store the plug-in settings store, backed by the repository's one `Preferences` instance.
 * @property coreSettings the settings panel's current core settings (the last applied snapshot plus the
 *   fields with no component). Read it on the EDT.
 * @property dialogParent the component dialogs should be parented to, or null before the panel is shown.
 * @property testConnection runs the core "Test connection" flow for a backend id, as a core card does.
 */
class SettingsContributionContext(
    val api: MontoyaApi,
    val store: PluginSettingsStore,
    val coreSettings: () -> AgentSettings,
    val dialogParent: () -> JComponent?,
    val testConnection: (backendId: String) -> Unit,
)

/**
 * Phase 29 / D-07, D-10 amended — the only route by which full-only UI reaches the settings window.
 *
 * The core `SettingsPanel` loads providers with `Plugins.load(SettingsContribution::class.java)`, which
 * uses the extension's own classloader, and imports no full-only panel. The store build ships no
 * `META-INF/services` file for this interface, so it loads none and its settings window is the core
 * one, unchanged. Providers MUST be classes with a public no-arg constructor (see [Plugins]).
 *
 * **Threading (UI-SPEC H-2).**
 * - [createComponent], [collect], [applyToUi] and [onCoreSettingsApplied] run on the EDT.
 * - [persist] runs on the `burp-ai-settings-save` worker, strictly after the core settings were saved,
 *   never on the EDT. It must not touch Swing: everything it writes comes from the snapshot.
 * - [defaults] may run on either thread and must not touch Swing.
 *
 * **Save.** A Save calls [collect] on the EDT together with the core snapshot, then [persist] on the
 * worker. A [persist] that throws reports through the bottom bar's "Save failed: {message}" line; core
 * settings already applied stay applied. **Restore defaults** calls `applyToUi(defaults())` on the EDT
 * and `persist(defaults(), store)` on the worker. Every core apply to the UI (load, save, restore) is
 * followed by [onCoreSettingsApplied].
 *
 * **Failure while building.** If [createComponent] throws, the host logs the contribution's class to
 * Burp's error output and drops it: none of its other members is called, and the window still opens.
 *
 * **Export hook (D-10 amended).** No settings export or import exists yet. [sectionId] and [ownedKeys]
 * are the members a future export would use: [sectionId] names the contribution's section in the
 * exported document and [ownedKeys] lists the preference keys it would carry.
 *
 * Contributions style only through `DesignTokens` getters and existing design components and cache no
 * color or font in a field, so they follow Burp's light and dark themes (UI-SPEC H-3).
 */
interface SettingsContribution {
    /** Stable, unique and non-blank. The section key a future export would use (D-10). */
    val sectionId: String

    val slot: SettingsSlot

    /**
     * For [SettingsSlot.BACKEND_CARD] only, and required there: the backend id whose card receives the
     * component. Ignored for the other slots.
     */
    val backendId: String? get() = null

    /**
     * Every preference key [persist] writes. Disjoint from the core `AgentSettings` keys; new keys are
     * prefixed `full.` and keys inherited from 1.0.1 keep their names (see [PluginSettingsStore]).
     */
    fun ownedKeys(): Set<String>

    /** EDT. Builds the component, reading initial values from [SettingsContributionContext.store]. */
    fun createComponent(context: SettingsContributionContext): JComponent

    /** EDT. Reads the contribution's Swing state only; no I/O. */
    fun collect(): ContributionSnapshot

    /** The `burp-ai-settings-save` worker, after the core save. Writes [snapshot] to [store]; no Swing. */
    fun persist(
        snapshot: ContributionSnapshot,
        store: PluginSettingsStore,
    )

    /** The values Restore defaults applies and persists. No Swing. */
    fun defaults(): ContributionSnapshot

    /** EDT. Shows [snapshot] in the contribution's components. */
    fun applyToUi(snapshot: ContributionSnapshot)

    /** EDT. Called after the host applied core [settings] to the UI. */
    fun onCoreSettingsApplied(settings: AgentSettings) {}
}
