package com.six2dez.burp.aiagent.ui

import burp.api.montoya.http.message.HttpRequestResponse
import java.awt.Component
import javax.swing.JOptionPane

/**
 * The targets of a context-menu action on a site-map subtree.
 *
 * Resolving them calls `api.siteMap().requestResponses(filter)`, which walks the WHOLE site map
 * (BApp #231 finding 1). That walk already stays out of menu construction because this is a [Lazy];
 * being this type is also the marker that tells [ContextTargetResolver] the resolution must run off the
 * EDT (Phase 33 EDT-01), because on a large project it freezes Burp for as long as it runs.
 *
 * [value] and [isInitialized] delegate to a synchronized `lazy`, so the walk runs at most once per menu
 * and a walk that throws is not memoized: the next action tries again. [logError] is the sink the
 * off-EDT worker reports a failed walk to.
 */
internal class SiteMapSubtreeTargets(
    val logError: (String) -> Unit,
    resolve: () -> List<HttpRequestResponse>,
) : Lazy<List<HttpRequestResponse>> {
    private val delegate = lazy(LazyThreadSafetyMode.SYNCHRONIZED, resolve)

    override val value: List<HttpRequestResponse>
        get() = delegate.value

    override fun isInitialized(): Boolean = delegate.isInitialized()
}

/**
 * Hands a context-menu action its resolved target list, on the EDT.
 *
 * A [SiteMapSubtreeTargets] that is not resolved yet is walked on the daemon thread
 * `burp-ai-agent-sitemap-resolve` through [OffEdtDispatch], and the action continues on the EDT with the
 * list, so its dialogs (and the counts they show) run on the EDT and use the real list. Every other
 * selection, and a subtree that is already resolved, continues inline with no thread hop.
 */
internal object ContextTargetResolver {
    /** The worker name a site-map walk runs under. */
    const val THREAD_NAME = "burp-ai-agent-sitemap-resolve"

    /** The [OffEdtDispatch] label of a site-map walk; it names the walk in the error log. */
    const val LABEL = "site map subtree"

    fun resolve(
        targets: Lazy<List<HttpRequestResponse>>,
        parent: Component?,
        onResolved: (List<HttpRequestResponse>) -> Unit,
    ) {
        if (targets !is SiteMapSubtreeTargets || targets.isInitialized()) {
            onResolved(targets.value)
            return
        }
        OffEdtDispatch.run(
            threadName = THREAD_NAME,
            label = LABEL,
            logError = targets.logError,
            work = { targets.value },
            onEdt = { result ->
                // The failure is already in the error log (OffEdtDispatch wrote it), so the dialog
                // carries no exception text; the action stops here.
                result.onSuccess(onResolved).onFailure {
                    JOptionPane.showMessageDialog(
                        parent,
                        "Could not read the selected site map subtree.",
                        "Custom AI Agent",
                        JOptionPane.WARNING_MESSAGE,
                    )
                }
            },
        )
    }
}
