package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.backends.BackendRegistry

internal fun unavailableBackendId(
    savedId: String,
    backends: BackendRegistry,
): String? = null

internal fun unavailableBackendNoticeHtml(id: String): String = ""
