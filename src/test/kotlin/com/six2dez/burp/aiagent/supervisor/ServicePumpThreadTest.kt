package com.six2dez.burp.aiagent.supervisor

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * REL-07 / SC6 — the service stdout pump in `AgentSupervisor.startService` runs on its own named
 * daemon thread.
 *
 * The pump calls `reader.forEachLine`, so it occupies its thread for the whole lifetime of the managed
 * service process (ollama-serve, lmstudio-server). Phase 23 D-05 put that unbounded-duration work on a
 * dedicated thread. This assertion used to live in `WorkerPoolExecutorTest`, beside the extension-wide
 * worker pool's contract; DEAD-01 (plan 29-05) deleted the pool, whose only remaining work was the
 * auto-restart submit, and this suite keeps the one guarantee from it that was never about the pool.
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which the PR gate passes. `ServicePumpThreadTest` ends in none of them.
 *
 * **Structural, from source on disk.** Nothing here spawns a service process. The source is read
 * through [SourceRoots.file], which fails when the file is in neither production root or in both, and
 * comment lines are stripped so the explanatory prose in `AgentSupervisor.kt` cannot satisfy or trip
 * the counts.
 */
class ServicePumpThreadTest {
    @Test
    fun startServiceNamesItsStdoutPumpThreadOnceAndMarksItDaemon() {
        val code = codeLinesOf(SUPERVISOR_SOURCE)

        assertEquals(
            1,
            code.count { it.contains(SERVICE_THREAD_NAME_PREFIX) },
            "REL-07 / SC6: `$SUPERVISOR_SOURCE` must name its service stdout pump thread exactly once, as " +
                "`$SERVICE_THREAD_NAME_PREFIX<name>`. Zero occurrences means the pump went onto a pool or onto " +
                "an anonymous thread, so a Burp thread dump no longer says which service owns it; more than " +
                "one means a second pump was introduced without going through this guard.",
        )

        val body = startServiceBody(code)
        assertTrue(
            body.any { it.contains(SERVICE_THREAD_NAME_PREFIX) },
            "REL-07 / SC6: the `$SERVICE_THREAD_NAME_PREFIX` thread must be created inside `startService`, " +
                "the method that launches the service process whose stdout it drains.",
        )

        val daemonLine = body.indexOfFirst { it.contains(SERVICE_PUMP_DAEMON_FLAG) }
        val startLine = body.indexOfFirst { it.contains(SERVICE_PUMP_START) }
        assertTrue(
            daemonLine >= 0,
            "REL-07 / SC6 (T-24-19): the service pump thread must set `$SERVICE_PUMP_DAEMON_FLAG` " +
                "explicitly. Phase 23 D-05 requires the flag be set rather than assumed: a non-daemon pump " +
                "holds the JVM open after Burp quits.",
        )
        assertTrue(
            startLine > daemonLine,
            "REL-07 / SC6: `$SERVICE_PUMP_START` must come after `$SERVICE_PUMP_DAEMON_FLAG`. " +
                "`Thread.setDaemon` throws once the thread has started, so a start before the flag " +
                "would fail every service launch. Found the flag at body line $daemonLine and the start " +
                "at $startLine.",
        )
    }

    /** The code lines of `startService`, from its declaration up to the next function declaration. */
    private fun startServiceBody(code: List<String>): List<String> {
        val start = code.indexOfFirst { it.contains(START_SERVICE_DECLARATION) }
        assertTrue(
            start >= 0,
            "Expected `$SUPERVISOR_SOURCE` to declare `$START_SERVICE_DECLARATION`. If the method was " +
                "renamed, re-aim this guard deliberately rather than deleting it.",
        )
        val rest = code.subList(start + 1, code.size)
        val next = rest.indexOfFirst { FUNCTION_DECLARATION.containsMatchIn(it) }
        return if (next < 0) rest else rest.subList(0, next)
    }

    /**
     * The non-comment lines of [path], read from disk. A line counts as a comment when its first
     * non-space characters are a line-comment marker, a continuation asterisk, or a block-comment
     * opener (the rule the other structural suites apply).
     */
    private fun codeLinesOf(path: String): List<String> =
        SourceRoots
            .file(path)
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }

    private companion object {
        const val SUPERVISOR_SOURCE = "com/six2dez/burp/aiagent/supervisor/AgentSupervisor.kt"
        const val SERVICE_THREAD_NAME_PREFIX = "burp-ai-agent-service-"
        const val SERVICE_PUMP_DAEMON_FLAG = "pumpThread.isDaemon = true"
        const val SERVICE_PUMP_START = "pumpThread.start()"
        const val START_SERVICE_DECLARATION = "private fun startService("
        val FUNCTION_DECLARATION = Regex("""^\s*(private |internal |override )*fun """)
    }
}
