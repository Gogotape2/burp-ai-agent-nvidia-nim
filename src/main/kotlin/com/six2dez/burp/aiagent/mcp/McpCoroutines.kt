package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.util.ExtensionThreads
import com.six2dez.burp.aiagent.util.ShutdownDeadline
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/*
 * Phase 33 / D-12 / LIFE-01 — the coroutine threads this extension owns.
 *
 * (A plain block comment, not KDoc: ktlint's `no-consecutive-comments` rule forbids a KDoc that is
 * immediately followed by another KDoc, and the KDoc below belongs to `McpCoroutines`.)
 *
 * ### Why
 * kotlinx.coroutines' shared dispatchers keep idle worker threads alive for 60 s after the last task and
 * name them `DefaultDispatcher-worker-N`, so after an unload a thread dump still shows coroutine workers
 * nobody can attribute, and nothing of ours stops them. Coroutine work this extension starts itself now
 * runs on [McpCoroutines.dispatcher]: a named daemon pool from `ExtensionThreads`
 * (`burp-ai-agent-mcp-coroutines-N`) that unload closes with [McpCoroutines.close]. Coroutines stay inside
 * the `mcp` package (CONVENTIONS.md).
 *
 * ### Covered
 * - The stdio bridge's own scope (`McpStdioBridge`).
 * - The Ktor server's parent coroutine context (`KtorMcpServerManager.start`, `parentCoroutineContext`),
 *   which the SSE `mcp {}` routes inherit: the MCP SDK has no dispatcher of its own on that path.
 *
 * ### Not redirectable, and how it is handled
 * - Ktor 3.1.3 hard-codes the shared IO dispatcher in `EmbeddedServer` start/stop and in its response
 *   plumbing; there is no injection point.
 * - The MCP SDK's `StdioServerTransport` builds its own scope on the shared IO dispatcher in its
 *   constructor, and its `close()` does not close the input source.
 * Both are handled at unload by [McpCoroutines.shutdownSharedDispatchers], guarded so it only ever touches
 * this extension's own copy of kotlinx.coroutines. Stdio is opt-in (off by default); when it is on and
 * Burp's stdin is a live terminal, the SDK reader stays blocked on `System.in`. That is an accepted
 * residual: closing `System.in` would break Burp itself, and the bounded join below keeps unload bounded.
 */

/**
 * The extension-owned coroutine dispatcher and the guarded shared-dispatcher shutdown (D-12).
 */
internal object McpCoroutines {
    /**
     * Same parallelism as the shared IO dispatcher, so blocking MCP tool calls are not starved. Idle
     * threads expire after [IDLE_KEEP_ALIVE_SECONDS], so an idle extension holds no threads.
     */
    const val MCP_COROUTINE_THREADS = 64
    private const val IDLE_KEEP_ALIVE_SECONDS = 60L

    private var executor: ThreadPoolExecutor? = null
    private var current: ExecutorCoroutineDispatcher? = null

    /**
     * The live extension-owned dispatcher. Builds a fresh one when none exists yet or the previous one
     * was closed, so a reload in the same classloader (or a test after a close) works again.
     */
    @Synchronized
    fun dispatcher(): CoroutineDispatcher {
        val live = current
        if (live != null && executor?.isShutdown == false) return live
        val pool =
            ExtensionThreads
                .boundedPool(
                    "mcp-coroutines",
                    MCP_COROUTINE_THREADS,
                    MCP_COROUTINE_THREADS,
                    IDLE_KEEP_ALIVE_SECONDS,
                    TimeUnit.SECONDS,
                    LinkedBlockingQueue(),
                    ThreadPoolExecutor.AbortPolicy(),
                ).apply { allowCoreThreadTimeOut(true) }
        executor = pool
        return pool.asCoroutineDispatcher().also { current = it }
    }

    /**
     * Stops the current dispatcher's threads within what is left of [deadline]; one Error line through
     * [logError] when they do not stop in time (D-09). A coroutine dispatched to it afterwards is
     * cancelled by kotlinx.coroutines (rejected execution); the next [dispatcher] call builds a new one.
     */
    fun close(
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
    ) {
        // Detach under the lock, wait outside it, so a concurrent dispatcher() call never waits on unload.
        val pool =
            synchronized(this) {
                executor.also {
                    executor = null
                    current = null
                }
            } ?: return
        pool.shutdown()
        deadline.awaitOrForce(pool, "MCP coroutines", logError)
        ExtensionThreads.release(pool)
    }

    /**
     * True only when kotlinx.coroutines' `Dispatchers` class was loaded by the extension's own
     * classloader: both non-null and the very same loader. A Burp that delegated `kotlinx.*` to its own
     * (parent) classloader makes this false, and the shared shutdown a no-op.
     */
    internal fun shouldShutdownShared(
        dispatchersLoader: ClassLoader?,
        extensionLoader: ClassLoader?,
    ): Boolean = dispatchersLoader != null && extensionLoader != null && dispatchersLoader === extensionLoader

    /**
     * Shuts down kotlinx.coroutines' shared dispatchers, which Ktor and the MCP SDK use internally and
     * which nothing else would stop after an unload.
     *
     * IRREVERSIBLE: it leaves kotlinx.coroutines inoperable for the rest of the classloader's life. Only the
     * production unload path (plan 33-09) and the dedicated unloadLeakTest JVM call it; NEVER call it from a
     * test in the shared test JVM. It runs only when [shouldShutdownShared] says the runtime is this
     * extension's own copy, so it can never stop Burp's or another extension's coroutines. It can hang on
     * a worker blocked in IO (measured: 15 s on a blocked pipe read, it never interrupts), so it runs on a
     * daemon thread joined for what is left of [deadline], with one Error line if it is still running.
     */
    @OptIn(DelicateCoroutinesApi::class)
    fun shutdownSharedDispatchers(
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
    ) {
        if (!shouldShutdownShared(Dispatchers::class.java.classLoader, McpCoroutines::class.java.classLoader)) return
        val thread = ExtensionThreads.newThread("coroutines-shutdown") { Dispatchers.shutdown() }
        thread.start()
        deadline.joinOrReport(thread, "kotlinx.coroutines dispatchers", logError)
    }
}
