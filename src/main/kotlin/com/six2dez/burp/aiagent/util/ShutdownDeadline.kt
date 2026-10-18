package com.six2dez.burp.aiagent.util

import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import kotlin.math.max

/*
 * LIFE-01 / D-05 / D-09 — one deadline for the whole unload.
 *
 * (A plain block comment, not KDoc: ktlint's `no-consecutive-comments` rule forbids a KDoc that is
 * immediately followed by another KDoc, and the KDoc below belongs to `ShutdownDeadline`.)
 *
 * ### AWT-free contract
 * Like `GuardedScheduling.kt`, this file MUST NOT import `java.awt.*` or `javax.swing.*`, and reports
 * through a `logError: (String) -> Unit` lambda rather than a `MontoyaApi`, so the unload path and
 * headless unit tests drive it the same way.
 */

/**
 * One monotonic unload budget shared by every shutdown step (D-05).
 *
 * Before D-05 each step had its own bounded wait, and the waits summed to about 60 s in the worst case,
 * all of it spent on Burp's unload path. Now the deadline is fixed once, at construction, and each step
 * gets only what is left: a slow first step shortens the waits after it instead of adding to them, and
 * once the budget is spent nothing waits at all — the remaining executors get `shutdownNow()`.
 *
 * Time comes from [nanoTime] (monotonic `System.nanoTime` in production), never the wall clock, so a
 * clock change during unload cannot stretch or skip the budget.
 *
 * D-09: a step that stops in time writes nothing; a step that did not stop writes exactly one Error line
 * naming its component ([deadlineMissed]). Every report goes through `runCatching`, because at unload the
 * Montoya logger is itself being torn down and a throwing sink must not escape into the unload path.
 *
 * A step that waits on work which cannot be interrupted (a Montoya HTTP call in flight) should call
 * `shutdownNow()` and NOT wait here; leave that wait to the final sweep
 * ([ExtensionThreadPools.terminateAll]), so the uninterruptible call costs the budget once, not per step.
 *
 * Public rather than internal because the public `McpServerManager` interface takes it as a parameter,
 * and Kotlin does not allow an `internal` member inside an interface.
 */
class ShutdownDeadline(
    budgetMs: Long,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private val endNanos: Long = nanoTime() + TimeUnit.MILLISECONDS.toNanos(max(0L, budgetMs))

    /** Milliseconds left before the deadline; never below 0. */
    fun remainingMs(): Long = max(0L, TimeUnit.NANOSECONDS.toMillis(endNanos - nanoTime()))

    /** True once no budget is left. */
    fun expired(): Boolean = remainingMs() == 0L

    /**
     * Waits for [executor] to terminate within the remaining budget; if it does not, forces it.
     *
     * The CALLER has already called `shutdown()` or `shutdownNow()`: each component chooses, because some
     * must not run their queued work during unload (the passive scanner, MCP). This only waits, and an
     * expired deadline means it does not wait at all.
     *
     * When the executor did not terminate in time, or the wait was interrupted, this calls `shutdownNow()`,
     * restores the interrupt flag if it was interrupted, writes one Error line naming [component] and
     * returns false. A clean stop returns true and writes nothing.
     */
    fun awaitOrForce(
        executor: ExecutorService,
        component: String,
        logError: (String) -> Unit,
    ): Boolean {
        var interrupted = false
        val stopped =
            try {
                executor.awaitTermination(remainingMs(), TimeUnit.MILLISECONDS)
            } catch (_: InterruptedException) {
                interrupted = true
                false
            }
        if (stopped) return true
        executor.shutdownNow()
        if (interrupted) Thread.currentThread().interrupt()
        report(deadlineMissed(component), logError)
        return false
    }

    /**
     * Joins [thread] for the remaining budget (at least 1 ms, since `join(0)` waits forever). Returns true
     * silently when the thread finished; otherwise writes one Error line naming [component] and returns
     * false. An interrupted join restores the flag.
     */
    fun joinOrReport(
        thread: Thread,
        component: String,
        logError: (String) -> Unit,
    ): Boolean {
        try {
            thread.join(max(1L, remainingMs()))
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (!thread.isAlive) return true
        report(deadlineMissed(component), logError)
        return false
    }

    companion object {
        /** The whole unload budget, in milliseconds (D-05). */
        const val UNLOAD_BUDGET_MS = 10_000L

        /** A fresh deadline with the whole [UNLOAD_BUDGET_MS]. */
        fun unload(): ShutdownDeadline = ShutdownDeadline(UNLOAD_BUDGET_MS)

        /** The Error line for a component that did not stop before the deadline (D-09). */
        fun deadlineMissed(component: String): String = "Unload: $component did not stop before the unload deadline"

        /** Writes [line] to [logError]; a throwing sink costs the line and nothing else. */
        fun report(
            line: String,
            logError: (String) -> Unit,
        ) {
            runCatching { logError(line) }
        }
    }
}
