package com.six2dez.burp.aiagent.scanner

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Phase 33 / D-02 (T-33-10) — turning the active scanner OFF stops attack traffic to the target.
 *
 * OFF calls `shutdownNow()` on the worker pool, which interrupts the workers. Before D-02 every payload
 * loop caught the interrupt in its broad `catch (e: Exception)` (the pacing `Thread.sleep` and the
 * `future.get` in `sendRequestWithTimeout` both throw `InterruptedException`), logged it as a payload
 * error and went on to send the next payload. Now the interrupt is restored and the loop is left.
 *
 * The target is a SQLi body parameter with up to ten payloads and a 1 s pacing delay, so a loop that
 * swallows the interrupt keeps sending well inside the observation window. The mocked
 * `api.http().sendRequest` counts every request on entry: a request on the wire is already counted, so
 * "no further request after OFF settled" means the count does not move afterwards.
 *
 * The only wall-clock wait is the observation window itself: it asserts that nothing happens.
 */
class ActiveScannerStopInterruptTest {
    private val rig = ActiveScannerRig()

    @AfterEach
    fun tearDown() {
        rig.close()
    }

    @Test
    fun afterOffSettlesNoFurtherRequestReachesTheTarget() {
        val scanner = attackingScanner()

        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (rig.sends.get() < 1) Thread.sleep(POLL_MS)
        }
        turnOffAndAwaitSettled(scanner)
        val atSettle = rig.sends.get()

        Thread.sleep(OBSERVATION_MS)

        assertEquals(
            atSettle,
            rig.sends.get(),
            "D-02: no request may reach the target after OFF settled; a payload loop swallowed the interrupt " +
                "and kept attacking. Error lines: ${rig.errorLines()}",
        )
    }

    @Test
    fun aRequestOnTheWireIsTheOnlyOneThatCompletesAfterOff() {
        val onWire = CountDownLatch(1)
        val release = CountDownLatch(1)
        rig.onSend = { sendNumber ->
            // Send 1 is the baseline; send 2 is the first payload, held on the wire across OFF.
            if (sendNumber == HELD_SEND) {
                onWire.countDown()
                awaitIgnoringInterrupts(release)
            }
        }
        try {
            val scanner = attackingScanner()
            assertTrue(onWire.await(AWAIT_SECONDS, TimeUnit.SECONDS), "the first payload must reach the wire")

            turnOffAndAwaitSettled(scanner)
            release.countDown()
            Thread.sleep(OBSERVATION_MS)

            assertEquals(
                HELD_SEND,
                rig.sends.get(),
                "D-02: only the request already on the wire may complete after OFF; the worker must not move " +
                    "on to the next payload. Error lines: ${rig.errorLines()}",
            )
        } finally {
            release.countDown()
        }
    }

    @Test
    fun theWorkersInterruptIsNotSwallowedAsAPayloadError() {
        val scanner = attackingScanner()

        // Send 1 is the baseline and send 2 the first payload, which answers at once; the worker then
        // sits in the 1 s pacing wait, which is where OFF's interrupt has to land for this case.
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (rig.sends.get() < HELD_SEND) Thread.sleep(POLL_MS)
        }
        Thread.sleep(INTO_PACING_WAIT_MS)
        val beforeOff = rig.errorLines().size
        turnOffAndAwaitSettled(scanner)
        Thread.sleep(QUIET_MS)

        // Phase 34 / D-04: matched on the log shape, not the exception message. A latch wait throws an
        // InterruptedException with a null message, so a message-based filter would pass even when the
        // interrupt were logged as "... error: null".
        val swallowed =
            rig.errorLines().drop(beforeOff).filter {
                it.contains("[ActiveAiScanner]") && it.contains("error:", ignoreCase = true)
            }
        assertTrue(
            swallowed.isEmpty(),
            "D-02: OFF's interrupt must end the payload loop, not be logged as a payload error: $swallowed",
        )
    }

    @Test
    fun offEndsALongPacingWaitAtOnce() {
        val scanner = attackingScanner(LONG_REQUEST_DELAY_MS)

        // Phase 34 / D-04 (SC3): with a 5 s delay the worker spends almost all of its time in the pacing
        // wait. OFF must end that wait at once, not when the delay runs out, and nothing more is sent.
        assertTimeoutPreemptively(Duration.ofSeconds(AWAIT_SECONDS)) {
            while (rig.sends.get() < HELD_SEND) Thread.sleep(POLL_MS)
        }
        Thread.sleep(INTO_PACING_WAIT_MS)
        val startNs = System.nanoTime()
        turnOffAndAwaitSettled(scanner)
        val settleMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs)
        val atSettle = rig.sends.get()

        assertTrue(
            settleMs < LONG_WAIT_SETTLE_BUDGET_MS,
            "D-04: OFF must end a ${LONG_REQUEST_DELAY_MS}ms pacing wait at once; it took ${settleMs}ms to settle",
        )
        Thread.sleep(QUIET_MS)
        assertEquals(
            atSettle,
            rig.sends.get(),
            "D-04: a pacing wait ended by OFF must not send another request. Error lines: ${rig.errorLines()}",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /** A running scanner attacking one SQLi target with ten payloads paced [requestDelayMs] apart (1 s by default). */
    private fun attackingScanner(requestDelayMs: Long = REQUEST_DELAY_MS): ActiveAiScanner {
        val scanner = rig.scanner()
        scanner.requestDelayMs = requestDelayMs
        scanner.maxPayloadsPerPoint = MAX_PAYLOADS
        scanner.setEnabled(true)
        scanner.queueTarget(rig.target(VulnClass.SQLI))
        return scanner
    }

    private fun turnOffAndAwaitSettled(scanner: ActiveAiScanner) {
        val settled = CountDownLatch(1)
        scanner.requestEnabled(false) { settled.countDown() }
        assertTrue(settled.await(AWAIT_SECONDS, TimeUnit.SECONDS), "OFF must settle")
    }

    private companion object {
        const val REQUEST_DELAY_MS = 1_000L
        const val MAX_PAYLOADS = 10
        const val HELD_SEND = 2
        const val OBSERVATION_MS = 2_500L
        const val QUIET_MS = 300L
        const val INTO_PACING_WAIT_MS = 200L
        const val LONG_REQUEST_DELAY_MS = 5_000L
        const val LONG_WAIT_SETTLE_BUDGET_MS = 1_500L
        const val AWAIT_SECONDS = 15L
        const val POLL_MS = 10L
    }
}
