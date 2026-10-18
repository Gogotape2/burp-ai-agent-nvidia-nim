package com.six2dez.burp.aiagent.backends.http

import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/*
 * Phase 34 / LOOP-01 / D-06 — the turn loop shared by the HTTP backend connections.
 *
 * Before this phase each connection ran a whole turn, retries included, as one task on its worker and
 * waited out the retry backoff with the old blocking backoff on that worker. The runner keeps every
 * visible number of that loop (attempt count, delays, circuit-breaker accounting, retry events) and
 * changes only the mechanism: the next attempt is a one-shot task on the connection's own scheduler,
 * and a stop cancels it at once.
 */

/**
 * Runs the turns of one HTTP backend connection, one at a time, with a scheduled retry backoff
 * (Phase 34 / D-06).
 *
 * Contract:
 * - **FIFO.** One active turn per runner. [submit] queues a turn; the next queued turn is dispatched
 *   only after the active turn's completion has run. A scheduled backoff therefore never lets a
 *   second turn mutate the connection's shared conversation history, so one feature's prompt or
 *   answer never rides along in another feature's retried request (RESEARCH Pitfall 1).
 * - **Attempts.** Before each attempt the circuit breaker must allow it (else the turn completes with
 *   [HttpBackendSupport.openCircuitError]) and the connection must be alive (else "Connection
 *   closed"). A retryable failure (see [HttpBackendSupport.isRetryableConnectionError]) is counted on
 *   the breaker and, unless it was the last of [MAX_ATTEMPTS], schedules the next attempt after
 *   [HttpBackendSupport.retryDelayMs] with one [BackendDiagnostics.logRetry] event.
 * - **Exactly once.** A turn's `onComplete` runs at most once, with no runner lock held. A callback
 *   that throws is logged through `errorLog` and neither runs again nor blocks the queue.
 * - **Stop.** [stop] cancels a pending retry at once and completes its turn with the last error, and
 *   completes every queued turn with "Connection closed". A turn submitted after the stop, or whose
 *   dispatch the executor rejects, also completes with "Connection closed".
 * - **Timer-free.** The runner never sleeps and never polls; the only delay is the scheduled task.
 *
 * @param executor the connection's one-thread scheduler (`ExtensionThreads.scheduled`); turns start on
 *   it and, by default, retries are scheduled on it.
 * @param retryLabel the backend id carried by [BackendDiagnostics.logRetry].
 * @param circuitName the display name used in the circuit-open error.
 * @param scheduleAfter test seam: schedules a task after a delay in milliseconds. It must never run
 *   the task inline, because the runner calls it under its lock.
 */
@Suppress("LongParameterList") // seven connection collaborators plus the test seam; a holder would only move them
internal class RetryingTurnRunner(
    private val executor: ScheduledExecutorService,
    private val retryLabel: String,
    private val circuitName: String,
    private val circuitBreaker: CircuitBreaker,
    private val isAlive: () -> Boolean,
    private val debugLog: (String) -> Unit,
    private val errorLog: (String) -> Unit,
    private val scheduleAfter: (Long, Runnable) -> Future<*> =
        { delayMs, task -> executor.schedule(task, delayMs, TimeUnit.MILLISECONDS) },
) {
    private class Turn(
        val prologue: () -> Unit,
        val attempt: (complete: (Throwable?) -> Unit) -> Unit,
        val onComplete: (Throwable?) -> Unit,
    ) {
        val completed = AtomicBoolean(false)

        @Volatile
        var lastError: Exception? = null

        /** The scheduled next attempt, if any. Guarded by the runner's lock. */
        var pending: Future<*>? = null
    }

    private val lock = Any()

    // Guarded by [lock].
    private val queue = ArrayDeque<Turn>()
    private var active: Turn? = null

    @Volatile
    private var stopped = false

    /**
     * Queues one turn. [prologue] runs once on the worker before the first attempt; [attempt] runs once
     * per attempt and must either call its `complete` argument or throw; [onComplete] receives the
     * turn's outcome exactly once. Never throws: a refused turn completes with "Connection closed".
     */
    fun submit(
        prologue: () -> Unit,
        attempt: (complete: (Throwable?) -> Unit) -> Unit,
        onComplete: (Throwable?) -> Unit,
    ) {
        val turn = Turn(prologue, attempt, onComplete)
        var refused = false
        var dispatchNow = false
        synchronized(lock) {
            when {
                stopped -> refused = true
                active == null -> {
                    active = turn
                    dispatchNow = true
                }
                else -> queue.addLast(turn)
            }
        }
        if (refused) {
            complete(turn, connectionClosed())
        } else if (dispatchNow) {
            dispatch(turn)
        }
    }

    /**
     * Stops the runner. Idempotent and callable from any thread. A pending retry is cancelled and its
     * turn completes with its last error; queued turns complete with "Connection closed". A turn whose
     * attempt is running is left to finish on the worker; its next check sees the stop.
     */
    fun stop() {
        val activeTurn: Turn?
        val pending: Future<*>?
        val queued: List<Turn>
        synchronized(lock) {
            stopped = true
            activeTurn = active
            pending = activeTurn?.pending
            activeTurn?.pending = null
            queued = queue.toList()
            queue.clear()
        }
        if (activeTurn != null && pending != null && pending.cancel(false)) {
            val last = activeTurn.lastError
            errorLog("exception: ${last?.message}")
            complete(activeTurn, last ?: connectionClosed())
        }
        queued.forEach { complete(it, connectionClosed()) }
    }

    private fun dispatch(turn: Turn) {
        try {
            executor.execute { startTurn(turn) }
        } catch (_: RejectedExecutionException) {
            complete(turn, connectionClosed())
        }
    }

    @Suppress("TooGenericExceptionCaught") // the prologue is caller code; any failure ends this turn, never the queue
    private fun startTurn(turn: Turn) {
        var started = false
        try {
            turn.prologue()
            started = true
        } catch (e: Exception) {
            errorLog("exception: ${e.message}")
            complete(turn, e)
        } finally {
            // An Error from the prologue: still complete the turn so the queue behind it moves.
            if (!started) complete(turn, endedWithoutResult())
        }
        if (started) runAttempt(turn, 0)
    }

    @Suppress("TooGenericExceptionCaught") // the attempt is caller code; every failure goes through the retry policy
    private fun runAttempt(
        turn: Turn,
        n: Int,
    ) {
        // A retry whose turn a stop already completed sends nothing.
        if (turn.completed.get()) return
        val refusal = attemptRefusal()
        if (refusal != null) {
            complete(turn, refusal)
            return
        }
        var thrown: Exception? = null
        try {
            turn.attempt { err -> complete(turn, err) }
        } catch (e: Exception) {
            thrown = e
        } finally {
            // A return without completing, or an Error: never leave the turn (and the queue) hanging.
            if (thrown == null && !turn.completed.get()) complete(turn, endedWithoutResult())
        }
        thrown?.let { onAttemptFailure(turn, n, it) }
    }

    /** Why the next attempt may not run, checked in the old loop's order: circuit breaker, then liveness. */
    private fun attemptRefusal(): Throwable? {
        val permission = circuitBreaker.tryAcquire()
        if (!permission.allowed) {
            val failFastError = HttpBackendSupport.openCircuitError(circuitName, permission.retryAfterMs)
            debugLog("circuit open: ${failFastError.message}")
            return failFastError
        }
        return if (!isAlive() || stopped) connectionClosed() else null
    }

    private fun onAttemptFailure(
        turn: Turn,
        n: Int,
        e: Exception,
    ) {
        if (turn.completed.get()) {
            errorLog("exception after completion: ${e.message}")
            return
        }
        turn.lastError = e
        val retryable = HttpBackendSupport.isRetryableConnectionError(e)
        if (retryable) {
            circuitBreaker.recordFailure()
        }
        if (!retryable || n == MAX_ATTEMPTS - 1) {
            errorLog("exception: ${e.message}")
            complete(turn, e)
            return
        }
        val delayMs = HttpBackendSupport.retryDelayMs(n)
        BackendDiagnostics.logRetry(retryLabel, n + 1, delayMs, e.message)
        debugLog("retrying in ${delayMs}ms after: ${e.message}")
        // Under the lock stop() takes: a stop either finds this pending retry (and cancels it) or this
        // check finds the stop (and completes the turn). No retry is scheduled behind a stop.
        val scheduled =
            synchronized(lock) {
                if (stopped) {
                    false
                } else {
                    try {
                        turn.pending = scheduleAfter(delayMs, Runnable { runAttempt(turn, n + 1) })
                        true
                    } catch (_: RejectedExecutionException) {
                        false
                    }
                }
            }
        if (!scheduled) {
            errorLog("exception: ${e.message}")
            complete(turn, e)
        }
    }

    @Suppress("TooGenericExceptionCaught") // a throwing caller callback is logged, never delivered twice
    private fun complete(
        turn: Turn,
        err: Throwable?,
    ) {
        if (!turn.completed.compareAndSet(false, true)) return
        try {
            turn.onComplete(err)
        } catch (e: Exception) {
            errorLog("onComplete failed: ${e.message}")
        } finally {
            afterCompletion(turn)
        }
    }

    private fun afterCompletion(turn: Turn) {
        var next: Turn? = null
        var drained: List<Turn> = emptyList()
        val alive = isAlive()
        synchronized(lock) {
            // A queued turn completed by stop() or a refused submit was never active: nothing moves.
            if (active !== turn) return
            if (!alive || stopped || executor.isShutdown) {
                active = null
                drained = queue.toList()
                queue.clear()
            } else {
                next = queue.removeFirstOrNull()
                active = next
            }
        }
        if (!alive) {
            executor.shutdownNow()
        }
        drained.forEach { complete(it, connectionClosed()) }
        next?.let { dispatch(it) }
    }

    private fun endedWithoutResult(): IllegalStateException = IllegalStateException("$circuitName request ended without a result")

    private companion object {
        /** Attempts per turn, unchanged from the old per-backend loops. */
        private const val MAX_ATTEMPTS = 6

        private fun connectionClosed(): IllegalStateException = IllegalStateException("Connection closed")
    }
}
