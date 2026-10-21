package com.six2dez.burp.aiagent.web

import java.io.InterruptedIOException

/** A per-worker signal prevents one cancelled chat from cancelling another chat's web request. */
internal object WebCancellation {
    private val signal = ThreadLocal<() -> Boolean>()

    fun current(): () -> Boolean = signal.get() ?: { false }

    fun check() {
        if (Thread.currentThread().isInterrupted || current().invoke()) throw InterruptedIOException("Web research cancelled")
    }

    fun <T> within(
        cancelled: () -> Boolean,
        work: () -> T,
    ): T {
        val previous = signal.get()
        signal.set(cancelled)
        try {
            check()
            return work()
        } finally {
            if (previous == null) signal.remove() else signal.set(previous)
        }
    }
}
