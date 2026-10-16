package com.six2dez.burp.aiagent.scanner

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/*
 * Phase 34 / D-04 (LOOP-01, SC3) — the active scanner's request pacing.
 *
 * (A plain block comment, not KDoc: ktlint's `no-consecutive-comments` rule forbids a KDoc that is
 * immediately followed by another KDoc, and the KDoc below belongs to `ScanPacing`.)
 *
 * The scanner waits `requestDelayMs` (0-5000 ms, user-set) between payloads at seven sites. Phase 33
 * made that wait interrupt-aware; this helper also ties it to the scanner's own stop signal.
 */

/**
 * A timed pacing wait that the scanner's stop ends at once (Phase 34 / D-04).
 *
 * [pause] waits up to the delay on a latch. [release] (OFF, unload) counts the latch down, so every
 * pause in progress returns now and every later pause of the same run returns at once; [reset] (the
 * next start) installs a fresh latch, so the new run's pauses wait the full delay again.
 *
 * Why a latch and not only the interrupt: `shutdownNow()` interrupts the workers, but an interrupt can be
 * swallowed somewhere on the way (a library catch, a cleared flag). The latch does not depend on it, so
 * OFF or unload ends the wait even then.
 *
 * [release] never throws into the worker: a released pause returns normally and the caller's halt check
 * (`haltRequested()` in `ActiveAiScanner`) stops the work. An interrupt still surfaces as
 * [InterruptedException] from [pause], so the existing Phase 33 / D-02 catch arms keep working.
 */
internal class ScanPacing {
    @Volatile
    private var stopSignal = CountDownLatch(1)

    /** Called on start: pauses of the new run wait the full delay again. */
    fun reset() {
        stopSignal = CountDownLatch(1)
    }

    /** Called on stop (OFF, unload): every pause ends now; later pauses of this run return at once. */
    fun release() {
        stopSignal.countDown()
    }

    /**
     * Waits up to [delayMs] (a negative value counts as zero) or until [release].
     *
     * @throws InterruptedException when the calling thread is, or becomes, interrupted.
     */
    fun pause(delayMs: Long) {
        // The boolean result (released vs timed out) is ignored on purpose: the caller decides by its
        // own halt check whether to go on.
        stopSignal.await(delayMs.coerceAtLeast(0L), TimeUnit.MILLISECONDS)
    }
}
