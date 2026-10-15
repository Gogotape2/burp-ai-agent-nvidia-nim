package com.six2dez.burp.aiagent.supervisor

import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.util.ExtensionThreads
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
 *
 * **Phase 33 / D-11.** The pump is built by `ExtensionThreads.newThread("service-$name")`, which names
 * it `burp-ai-agent-service-<name>` and sets the daemon flag explicitly on every thread it builds, so
 * the source no longer carries a separate `isDaemon` line. The structural case pins the helper call;
 * the behavioural case pins the resulting name and daemon flag for both fixed service labels.
 */
class ServicePumpThreadTest {
    @Test
    fun startServiceBuildsItsStdoutPumpThreadOnceThroughTheHelperAndStartsIt() {
        val code = codeLinesOf(SUPERVISOR_SOURCE)

        assertEquals(
            1,
            code.count { it.contains(SERVICE_PUMP_BUILDER) },
            "REL-07 / SC6: `$SUPERVISOR_SOURCE` must build its service stdout pump thread exactly once, " +
                "through `$SERVICE_PUMP_BUILDER`. Zero occurrences means the pump went onto a pool or onto " +
                "an anonymous thread, so a Burp thread dump no longer says which service owns it; more than " +
                "one means a second pump was introduced without going through this guard.",
        )

        val body = startServiceBody(code)
        val builderLine = body.indexOfFirst { it.contains(SERVICE_PUMP_BUILDER) }
        val startLine = body.indexOfFirst { it.contains(SERVICE_PUMP_START) }
        assertTrue(
            builderLine >= 0,
            "REL-07 / SC6: the pump thread must be built inside `startService`, the method that launches " +
                "the service process whose stdout it drains.",
        )
        assertTrue(
            startLine > builderLine,
            "REL-07 / SC6: `$SERVICE_PUMP_START` must come after the pump is built. Found the builder at " +
                "body line $builderLine and the start at $startLine.",
        )
    }

    @Test
    fun theHelperNamesEveryServicePumpWithTheServicePrefixAndMarksItDaemon() {
        SERVICE_LABELS.forEach { label ->
            val pump = ExtensionThreads.newThread("service-$label") {}

            assertEquals(
                "$SERVICE_THREAD_NAME_PREFIX$label",
                pump.name,
                "REL-07 / SC6: the `$label` pump must be named `$SERVICE_THREAD_NAME_PREFIX<name>` in a thread dump",
            )
            assertTrue(
                pump.isDaemon,
                "REL-07 / SC6 (T-24-19): the `$label` pump must be daemon: a non-daemon pump holds the JVM " +
                    "open after Burp quits (Phase 23 D-05).",
            )
        }
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
        const val SERVICE_PUMP_BUILDER = "ExtensionThreads.newThread(\"service-\$name\")"
        const val SERVICE_PUMP_START = "pumpThread.start()"
        val SERVICE_LABELS = listOf("ollama-serve", "lmstudio-server")
        const val START_SERVICE_DECLARATION = "private fun startService("
        val FUNCTION_DECLARATION = Regex("""^\s*(private |internal |override )*fun """)
    }
}
