package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.util.ShutdownDeadline
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

/**
 * Phase 33 / WR-03, D-05, D-06, D-09 — hands unload teardown to the Swing EDT without waiting on it past
 * the shared unload deadline.
 *
 * Swing teardown still runs on the EDT (D-06), but Burp's unload handler runs on a Montoya thread, and a
 * busy EDT (a modal dialog, a long repaint) used to hold an unbounded `invokeAndWait` in
 * `MainTab.dispose` and `ChatPanel.shutdown` for as long as it stayed busy, past the D-05 budget and with
 * no line saying why. [runWithin] posts the work instead and waits at most what is left of the deadline;
 * when the EDT does not run it in time it writes exactly one Error line naming the component
 * ([ShutdownDeadline.deadlineMissed], D-09) and returns, and the posted work still runs once the EDT is
 * free. [post] never waits at all, the precedent `ActiveScanQueuePanel.disposeOpenDialogs` set for its
 * queue dialogs.
 *
 * On the EDT both run the work inline: waiting there would wait on the very thread that must run it.
 *
 * A work that throws writes one line in `App.safeShutdownStep`'s wording,
 * `"<component> shutdown failed: <message>"`, and nothing escapes into Swing's exception handler or the
 * unload path. Lines carry the fixed component label and the exception's message only.
 *
 * It lives in `ui/` rather than next to [ShutdownDeadline] because that file is AWT-free by contract.
 * It creates no thread: the only threads involved are the caller's and the EDT.
 */
internal object EdtTeardown {
    /**
     * Runs [work] on the EDT and waits for it at most [deadline]'s remaining budget.
     *
     * Returns true when the work ran in time (a work that threw counts, after its failure line). Returns
     * false, after one [ShutdownDeadline.deadlineMissed] line for [component], when the EDT did not run it
     * in time or the wait was interrupted (the interrupt flag is restored).
     */
    fun runWithin(
        component: String,
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
        work: () -> Unit,
    ): Boolean {
        if (SwingUtilities.isEventDispatchThread()) {
            runGuarded(component, logError, work)
            return true
        }
        val done = CountDownLatch(1)
        SwingUtilities.invokeLater {
            try {
                runGuarded(component, logError, work)
            } finally {
                done.countDown()
            }
        }
        val finished =
            try {
                done.await(deadline.remainingMs(), TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                false
            }
        if (!finished) ShutdownDeadline.report(ShutdownDeadline.deadlineMissed(component), logError)
        return finished
    }

    /** Runs [work] on the EDT: inline when already there, otherwise posted. Never waits. */
    fun post(
        component: String,
        logError: (String) -> Unit,
        work: () -> Unit,
    ) {
        if (SwingUtilities.isEventDispatchThread()) {
            runGuarded(component, logError, work)
        } else {
            SwingUtilities.invokeLater { runGuarded(component, logError, work) }
        }
    }

    // Teardown on the EDT must not throw into Swing's exception handler, and must not skip the latch
    // runWithin's waiter counts on, whatever the work throws; hence the Throwable catch.
    @Suppress("TooGenericExceptionCaught")
    private fun runGuarded(
        component: String,
        logError: (String) -> Unit,
        work: () -> Unit,
    ) {
        try {
            work()
        } catch (t: Throwable) {
            ShutdownDeadline.report("$component shutdown failed: ${t.message}", logError)
        }
    }
}
