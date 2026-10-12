package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.BackendRegistry

/** UI-SPEC P-4: longest stored id the notice shows before cutting it. */
private const val MAX_NOTICE_ID_CHARS = 64

/**
 * Phase 29 / D-08 (UI-SPEC S5/S8): the saved backend id when this build does not offer it, else `null`.
 *
 * The single condition both notices (Main tab S5, Settings S8) and both pickers use, so they cannot
 * disagree. "Offered" means listed in the pickers, which list exactly the registry's ids.
 */
internal fun unavailableBackendId(
    savedId: String,
    backends: BackendRegistry,
): String? = if (savedId in backends.listAllBackendIds()) null else savedId

/**
 * Copy C-N1 for [id]. [SubtleNotice][com.six2dez.burp.aiagent.ui.components.SubtleNotice] renders
 * HTML and the id is user-writable preference data, so it is cut to 64 characters plus "…" and then
 * HTML-escaped before interpolation (UI-SPEC P-4 / PC-1, T-29-43; same reasoning as SCAN-02).
 */
internal fun unavailableBackendNoticeHtml(id: String): String {
    val shown = if (id.length > MAX_NOTICE_ID_CHARS) id.take(MAX_NOTICE_ID_CHARS) + "\u2026" else id
    val escaped =
        shown
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;")
    return "Saved backend '$escaped' is not available in this build; using Burp AI. Pick another backend to replace it."
}
