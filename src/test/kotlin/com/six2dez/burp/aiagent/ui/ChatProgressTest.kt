package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class ChatProgressTest {
    @Test
    fun retriesAndToolTransitionsKeepTheTaskClockAndOnlyRestartThePhaseClock() {
        val start = TimeUnit.SECONDS.toNanos(10)
        val progress = ChatProgress(start)
        progress.phase("provider", now = start + TimeUnit.SECONDS.toNanos(1))
        progress.phase("provider", now = start + TimeUnit.SECONDS.toNanos(20))
        assertEquals(start + TimeUnit.SECONDS.toNanos(1), progress.phaseStartedAtNanos)
        val retry = progress.phase("retry", "HTTP 429; retry 1 after 5000ms", start + TimeUnit.SECONDS.toNanos(61)).orEmpty()
        assertTrue(retry.contains("HTTP 429") && retry.contains("5000"))
        val label = ChatProgress.elapsedLabel(retry, progress.startedAtNanos, progress.phaseStartedAtNanos, start + TimeUnit.SECONDS.toNanos(63))
        assertTrue(label.contains("всего 1:03") && label.contains("этап 0:02"))
        assertTrue(progress.phase("tool", "context_read", start + TimeUnit.SECONDS.toNanos(65)).orEmpty().contains("context_read"))
        assertEquals(start, progress.startedAtNanos)
    }
}
