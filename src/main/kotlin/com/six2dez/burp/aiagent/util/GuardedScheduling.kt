package com.six2dez.burp.aiagent.util

import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/*
 * REL-06 — fault containment for recurring scheduled tasks.
 *
 * (A plain block comment, not KDoc: ktlint's `no-consecutive-comments` rule forbids a KDoc that is
 * immediately followed by another KDoc, and the KDoc below belongs to `runGuarded`.)
 *
 * ### The failure mode this file exists to prevent
 * A recurring `scheduleAtFixedRate` / `scheduleWithFixedDelay` task is **silently cancelled for the
 * rest of the JVM's life** if any single run lets a throwable escape. The JDK suppresses every
 * subsequent execution, nothing is written to any log, and the only observable signal is `isDone()`
 * on the returned `ScheduledFuture` — a value this codebase discards at every scheduling site. The
 * production symptom is therefore indistinguishable from "nothing is happening": the active scanner
 * queue stops draining and the Burp error log stays empty.
 *
 * That reasoning was first written inline above the health monitor's guard in
 * [com.six2dez.burp.aiagent.supervisor.AgentSupervisor]; it moves here because the guarantee now has
 * to hold at five scheduling sites rather than one.
 *
 * ### Two places at once (Phase 23 D-02)
 * The mechanism below is only half of the guarantee. `SchedulerGuardCoverageTest` is the other half:
 * it reads every file under `src/main/kotlin` and fails the build if a recurring schedule appears
 * outside the small allowlist of sites that carry an inline guard. A helper nobody is required to
 * call is a helper the sixth call site will skip.
 *
 * ### AWT-free contract
 * This file MUST NOT import `java.awt.*` or `javax.swing.*`, and it deliberately takes a
 * `logError: (String) -> Unit` lambda rather than a `MontoyaApi`, so a caller that logs through its
 * own callback needs no Burp dependency, and the whole file stays drivable from a headless unit test.
 */

/**
 * Runs [body], absorbing anything it throws and reporting it through [logError] as
 * `[component] task failed: message`, the format `CONVENTIONS.md` §Error Handling mandates.
 *
 * Logs **only** on a throw: a successful or no-op run produces zero lines. `processQueue()` ticks
 * over an empty queue several times a second, so a guard that also logged the success path would
 * flood Burp's error log.
 *
 * This function never rethrows. That is the entire contract — the caller is a recurring scheduled
 * task whose next execution depends on nothing escaping. The contract covers [logError] as well as
 * [body]: a caller-supplied sink that throws is absorbed too, because a guard that lets its own
 * reporting escape cancels the schedule exactly as surely as an unguarded body does.
 *
 * **An in-file suppression of `TooGenericExceptionCaught` rather than a regenerated baseline.** Catching
 * [Throwable] is the requirement, not an oversight: the JDK suppresses all subsequent executions on
 * **any** throwable reaching the task, an `Error` included, so narrowing the catch to `Exception`
 * would reopen the defect for exactly the cases that are hardest to reproduce. `detekt-baseline.xml`
 * is a held v0.10.0 milestone metric at 1096 entries which QUAL-07 forbids growing, and its entries
 * are exact strings keyed per file — a new file's finding is never covered by an existing entry, so
 * the baseline is not an option here even in principle. The two pre-existing guards
 * (`AgentSupervisor.kt` health check, `ActiveAiScanner.kt` OAST poller) catch `Throwable` for the
 * same reason.
 */
@Suppress("TooGenericExceptionCaught")
internal fun runGuarded(
    component: String,
    task: String,
    logError: (String) -> Unit,
    body: () -> Unit,
) {
    try {
        body()
    } catch (e: Throwable) {
        try {
            logError("[$component] $task failed: ${e.message}")
        } catch (_: Throwable) {
            // INTENTIONAL: absorbed, not reported. [logError] is caller-supplied and is not required to
            // be self-guarding, so it can throw — a torn-down `MontoyaApi` is the obvious case. Letting
            // that throw escape would reach the JDK scheduler and cancel the recurring task permanently,
            // re-opening the very defect this guard closes. There is by construction nowhere left to
            // report it: the reporting channel is the thing that just failed.
        }
    }
}

/**
 * Schedules [body] to run repeatedly with a fixed delay, wrapped in [runGuarded] so a throw on one
 * tick cannot cancel the ticks after it.
 *
 * [body] is the last parameter so call sites read as a trailing lambda, keeping the migrated sites
 * visually close to the direct JDK calls they replace. detekt's `LongParameterList` threshold is 10
 * in `detekt.yml`, so seven parameters is within budget.
 *
 * The returned future is handed back rather than dropped, so a caller that wants to cancel the
 * schedule can; every current call site legitimately ignores it because the owning executor is shut
 * down as a whole.
 */
internal fun ScheduledExecutorService.scheduleGuarded(
    component: String,
    task: String,
    logError: (String) -> Unit,
    initialDelay: Long,
    delay: Long,
    unit: TimeUnit,
    body: () -> Unit,
): ScheduledFuture<*> =
    scheduleWithFixedDelay(
        { runGuarded(component, task, logError, body) },
        initialDelay,
        delay,
        unit,
    )
