package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 33 / D-06, D-12 — the unload order in `App.shutdown`, read from App.kt's source.
 *
 * Structural on purpose: App-level tests that run the unload live only in the dedicated
 * `unloadLeakTest` JVM, and the ORDER is what makes the unload correct, so it is pinned here in the
 * normal `test` task. The AI side is latched before anything else (CR-01: the supervisor refuses every
 * AI request and stops the turns in flight), so no later step's duration opens a window for AI traffic.
 * Inbound work stops next (MCP, then plug-ins and scanners), then the AI side
 * (chat supervisor, backends), then the UI and the global sinks, then the sweep; the irreversible
 * shared coroutine shutdown runs only when the caller asks for it.
 */
class AppShutdownOrderTest {
    @Test
    fun unloadStepsRunInboundFirstInTheD06Order() {
        val body = shutdownBody()
        var previous = -1
        var previousLabel = "(start)"
        for (label in STEP_LABELS) {
            val index = body.indexOf("safeShutdownStep(\"$label")
            assertTrue(index >= 0, "App.shutdown has no step labelled \"$label\"")
            assertTrue(index > previous, "step \"$label\" must come after \"$previousLabel\"")
            previous = index
            previousLabel = label
        }
    }

    @Test
    fun unloadEndsWithTheSweepAndAGuardedSharedCoroutineShutdown() {
        val body = shutdownBody()

        assertTrue(body.contains("ExtensionThreads.terminateAll("), "the final sweep must run")
        assertEquals(
            1,
            Regex("""McpCoroutines\.shutdownSharedDispatchers\(""").findAll(body).count(),
            "the shared coroutine shutdown appears exactly once",
        )
        val guard = body.indexOf("if (shutdownSharedCoroutines)")
        assertTrue(guard >= 0, "the shared coroutine shutdown must sit behind if (shutdownSharedCoroutines)")
        val guardedBlock = body.substring(guard, body.indexOf("\n        }", guard))
        assertTrue(
            guardedBlock.contains("McpCoroutines.shutdownSharedDispatchers("),
            "McpCoroutines.shutdownSharedDispatchers( must be inside the if (shutdownSharedCoroutines) block",
        )
        assertTrue(
            body.indexOf("ExtensionThreads.terminateAll(") < guard,
            "the shared coroutine shutdown runs after the sweep",
        )
    }

    /** The comment-stripped body of `fun shutdown(` in App.kt: from its signature to its closing brace. */
    private fun shutdownBody(): String {
        // A Windows checkout is CRLF (core.autocrlf; .gitattributes pins only BappManifest.bmf to LF) and the markers below are LF-based.
        val source = SourceRoots.file("com/six2dez/burp/aiagent/App.kt").readText().replace("\r\n", "\n")
        val start = source.indexOf("\n    fun shutdown(")
        assertTrue(start >= 0, "fun shutdown( not found in App.kt")
        val end = source.indexOf("\n    }\n", start)
        assertTrue(end > start, "the end of fun shutdown( not found in App.kt")
        return source
            .substring(start, end)
            .lines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }.joinToString("\n")
    }

    private companion object {
        val STEP_LABELS =
            listOf(
                "AI unload latch",
                "MainTab quiesce",
                "MCP supervisor",
                "Plug-in",
                "Passive scanner",
                "Active scanner",
                "Supervisor",
                "Backend registry",
                "AI Request Logger",
                "MainTab dispose",
                "Redaction mappings",
                "Redaction truncation sink",
                "MCP coroutines",
                "Thread sweep",
                "Shared coroutine dispatchers",
            )
    }
}
