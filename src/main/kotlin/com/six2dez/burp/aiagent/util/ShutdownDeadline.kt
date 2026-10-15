package com.six2dez.burp.aiagent.util

import java.util.concurrent.ExecutorService

/** RED skeleton: signatures only; behaviour lands in the GREEN commit. */
internal class ShutdownDeadline(
    private val budgetMs: Long,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    fun remainingMs(): Long = budgetMs

    fun expired(): Boolean = false

    fun awaitOrForce(
        executor: ExecutorService,
        component: String,
        logError: (String) -> Unit,
    ): Boolean = true

    fun joinOrReport(
        thread: Thread,
        component: String,
        logError: (String) -> Unit,
    ): Boolean = true

    companion object {
        const val UNLOAD_BUDGET_MS = 10_000L

        fun unload(): ShutdownDeadline = ShutdownDeadline(UNLOAD_BUDGET_MS)
    }
}
