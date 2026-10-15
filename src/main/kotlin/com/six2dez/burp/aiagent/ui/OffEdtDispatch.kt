package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.util.ExtensionThreads
import javax.swing.SwingUtilities

/**
 * The single place chat work leaves the AWT Event Dispatch Thread, and the single place it returns.
 *
 * REL-05: a tool call reaches Burp through `api.http()`, which must not be entered from the EDT, and
 * which freezes the whole Burp UI for as long as it runs there. [run] takes the work off the EDT onto
 * a short-lived **named daemon** thread and marshals its outcome back through exactly ONE
 * `SwingUtilities.invokeLater` — the `MainTab.kt:190-215` idiom, with the daemon flag that idiom omits.
 *
 * **After the dispatch statement, nothing here waits on the worker.** The counter-example lives in this
 * repo: `MontoyaHttpTransport.execute` offloads and then blocks the calling thread on the worker's
 * result, which dodges Burp's EDT exception while leaving the UI just as frozen. Offloading and
 * freeing the UI are two different things, and only the second is what REL-05 asks for.
 *
 * Concurrency is `java.util.concurrent` plus JDK Swing, per CONVENTIONS.md:95 (no other concurrency
 * layer outside the `mcp` package) and D-05 (no panel-owned executor pool).
 *
 * The `Result<T>` crosses the thread boundary **intact**: the EDT tail needs the real `Throwable`, not
 * a stringified one, because `ChatPanel.reportFailedToolCall` keys its SC3 `errorClass` field off the
 * throwable's own class.
 */
internal object OffEdtDispatch {
    /**
     * Fired with the dispatch label from the EDT tail's `finally`, i.e. when the work is **finished**
     * and its tail has already run on the EDT.
     *
     * Null in production; it exists so a test can synchronise on a daemon worker it cannot see.
     * `McpToolExecutor` is an `object` singleton referenced statically at every call site, so there is
     * no executor double to put a latch in — the hook has to hang off the dispatch helper itself.
     * Install/clear discipline follows `AuditLogger.registerGlobalEmitter`: `@Volatile`, nullable, and
     * a nullable-accepting register function so `register(null)` is the clear.
     */
    @Volatile
    private var settledObserver: ((String) -> Unit)? = null

    /**
     * Fired with the dispatch label the instant a worker is **started**, on the calling thread.
     *
     * **Two observers, not one, because they record different moments and a test needs to tell them
     * apart.** A test asserting that NO worker ever ran cannot read [settledObserver]'s record: in the
     * buggy world such a test exists to catch — a call that dispatched a worker it should not have —
     * that worker has not finished at assert time, so its label is absent from the settle record too
     * and the assertion passes while the bug is present. This observer is invoked synchronously with
     * the dispatch statement, so a started worker is visible immediately and its absence is a real
     * claim rather than a timing artefact.
     *
     * Same production-null contract and same install/clear discipline as [settledObserver].
     */
    @Volatile
    private var dispatchedObserver: ((String) -> Unit)? = null

    /** Installs (or, with `null`, clears) the completion hook. See [settledObserver]. */
    fun registerSettledObserver(observer: ((String) -> Unit)?) {
        settledObserver = observer
    }

    /** Installs (or, with `null`, clears) the start-of-work hook. See [dispatchedObserver]. */
    fun registerDispatchedObserver(observer: ((String) -> Unit)?) {
        dispatchedObserver = observer
    }

    /**
     * Runs [work] on a named daemon thread and hands its [Result] to [onEdt] on the EDT.
     *
     * Returns as soon as the thread is started. [label] identifies this unit of work in the two
     * observers and in the error log — callers pass a trace id, so an ordering assertion can select by
     * identity instead of by list position.
     *
     * [logError] is the caller's error sink (`api.logging().logToError`). A worker throwing on a thread
     * Burp did not create is a throwable nobody would otherwise see, so both the work and the EDT tail
     * are wrapped and routed to it.
     *
     * **Every sink on the path to the single `invokeLater` is itself wrapped, so the resulting contract
     * is that the EDT tail is unreachable only if `SwingUtilities.invokeLater` itself fails (CR-04).**
     * `logError` is a Montoya API handle at every production call site, and a handle whose extension has
     * been unloaded is not guaranteed to keep accepting calls — which is exactly the co-occurring
     * condition here, since the failure-path sink is reached only when `work` failed and one reason
     * `work` fails is that the extension is tearing down. Unwrapped, a throwing logger killed the
     * runnable outright: the tail never ran, so `ChatPanel` never cleared its busy state, `runningTool`
     * kept a token nobody would clear, the completion callback was silently dropped, and the panel sat
     * in UI-SPEC state S3 — Send hidden, input disabled — for the rest of the Burp session with nothing
     * running. A throwing sink must cost a log line and nothing else.
     *
     * [dispatchedObserver] is deliberately NOT wrapped, and that asymmetry is a decision rather than an
     * oversight. It is invoked on the CALLING thread before any dispatch exists, so nothing downstream
     * depends on it and a throw there is the caller's own bug — one that must stay visible instead of
     * being swallowed inside a helper. Wrapping it would buy nothing and hide something.
     *
     * The worker comes from [ExtensionThreads.newThread] (D-11), which sets the daemon flag explicitly —
     * a non-daemon worker can hold extension unload open, and the EDT that calls this is non-daemon — and
     * names it `burp-ai-agent-<threadName>`, so a stuck worker is identifiable in a thread dump. A
     * [threadName] that already starts with `burp-ai-agent-` is used as given; any other gets the prefix.
     */
    fun <T> run(
        threadName: String,
        label: String,
        logError: (String) -> Unit,
        work: () -> T,
        onEdt: (Result<T>) -> Unit,
    ) {
        // FIRST STATEMENT, and that placement is load-bearing rather than stylistic: the start of work
        // is recorded on the CALLING thread, synchronously with the dispatch below. Recorded from the
        // worker instead, it would race any assertion that reads it.
        dispatchedObserver?.invoke(label)
        val body =
            Runnable {
                val outcome = runCatching(work)
                outcome.exceptionOrNull()?.let { failure ->
                    runCatching { logError("[OffEdtDispatch] $label failed off the EDT: ${failure.javaClass.simpleName}: ${failure.message}") }
                }
                SwingUtilities.invokeLater {
                    try {
                        // The tail runs on the EDT; a throwable escaping it would otherwise be swallowed
                        // by the AWT event pump's default handler with no entry in Burp's error log.
                        runCatching { onEdt(outcome) }
                            .exceptionOrNull()
                            ?.let { failure ->
                                runCatching { logError("[OffEdtDispatch] $label failed in its EDT tail: ${failure.javaClass.simpleName}: ${failure.message}") }
                            }
                    } finally {
                        // In the `finally`, so the work is recorded as settled even when the tail threw.
                        runCatching { settledObserver?.invoke(label) }
                    }
                }
            }
        ExtensionThreads.newThread(threadName.removePrefix(ExtensionThreads.PREFIX), body).start()
    }
}
