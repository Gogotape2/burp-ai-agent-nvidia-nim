package com.six2dez.burp.aiagent.util

import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.BlockingQueue
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionHandler
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/*
 * LIFE-03 / D-11 — the one place the extension builds threads.
 *
 * (A plain block comment, not KDoc: ktlint's `no-consecutive-comments` rule forbids a KDoc that is
 * immediately followed by another KDoc, and the KDocs below belong to the declarations.)
 *
 * ### The only production place allowed to construct a thread
 * This file is the ONLY production code allowed to construct a `Thread`, a `ThreadFactory` or a thread
 * pool. Every other site asks it for one by naming a subsystem. A later Phase 33 plan adds a source
 * guard test that fails the build when a thread is constructed anywhere else; a helper nobody is
 * required to call is a helper the next call site will skip.
 *
 * ### Why
 * - A Burp thread dump must attribute every thread to this extension and to one subsystem. An
 *   anonymous `pool-7-thread-3` or `Thread-42` says nothing about who owns a stuck thread.
 * - Kotlin's and Java's `Thread` inherit the CREATOR's daemon flag, and the AWT Event Dispatch Thread is
 *   non-daemon. A worker started from a click is therefore non-daemon unless someone says otherwise,
 *   and a non-daemon thread holds extension unload open. Every thread built here is daemon, explicitly.
 * - The BApp Store reviewer reads these names.
 * - Every pool built here is tracked, so the unload sweep ([ExtensionThreadPools.terminateAll]) can
 *   force whatever its owner forgot to stop (D-09).
 *
 * ### Names carry no data
 * A name is `burp-ai-agent-<subsystem>` or `burp-ai-agent-<subsystem>-N`, built ONLY from a fixed
 * subsystem label written in source. It never carries a session id, URL, host, prompt or any value
 * taken from traffic or from the user, because thread dumps are shared with PortSwigger reviewers and
 * pasted into bug reports. The label is validated against `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, which
 * rejects URLs, `host:port` pairs and free text, and the rejection message carries the value's length
 * only, never the value.
 *
 * ### AWT-free contract
 * Like `GuardedScheduling.kt`, this file MUST NOT import `java.awt.*` or `javax.swing.*`, and reports
 * through a `logError: (String) -> Unit` lambda rather than a `MontoyaApi`, so registries, backends and
 * headless unit tests can all use it.
 */

/**
 * The thread helper's logic, as a class so a test can build a private instance and never sweep the
 * shared one. Production uses the process-wide [ExtensionThreads] object.
 */
internal open class ExtensionThreadPools {
    /**
     * Every pool built by this instance that has not been released, mapped to its subsystem label.
     *
     * Weakly keyed: a pool its owner dropped without ever starting a worker can be collected, which is
     * harmless because it has nothing to stop. A pool with a live worker stays strongly reachable from
     * that worker (the worker thread holds the pool's `Worker`, which holds the pool), so weak tracking
     * never loses a running pool.
     */
    private val tracked: MutableMap<ExecutorService, String> =
        Collections.synchronizedMap(WeakHashMap())

    /**
     * A thread factory whose threads are daemon and named `burp-ai-agent-<subsystem>-N` ([numbered]) or
     * `burp-ai-agent-<subsystem>`.
     *
     * The counter belongs to this factory, so each pool numbers its own threads from 1 and two pools of
     * one subsystem may share names: a name identifies the subsystem, not the instance.
     *
     * @throws IllegalArgumentException when [subsystem] is blank, already starts with the prefix, or is
     *   not a short label of `[A-Za-z0-9._-]`.
     */
    fun factory(
        subsystem: String,
        numbered: Boolean = true,
    ): ThreadFactory {
        validate(subsystem)
        val base = ExtensionThreads.PREFIX + subsystem
        val counter = AtomicInteger(0)
        return ThreadFactory { runnable ->
            val name = if (numbered) "$base-${counter.incrementAndGet()}" else base
            Thread(runnable, name).apply { isDaemon = true }
        }
    }

    /**
     * An UNSTARTED daemon thread named `burp-ai-agent-<subsystem>`. Not tracked: the caller starts it.
     * For short-lived workers and shutdown helpers, never for a long-lived loop nobody joins.
     */
    fun newThread(
        subsystem: String,
        body: Runnable,
    ): Thread = factory(subsystem, numbered = false).newThread(body)

    /** A tracked single-thread executor whose worker is `burp-ai-agent-<subsystem>`. */
    fun singleThread(subsystem: String): ExecutorService =
        track(
            subsystem,
            ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue(), factory(subsystem, numbered = false)),
        )

    /**
     * A tracked one-thread scheduler whose worker is `burp-ai-agent-<subsystem>`.
     *
     * Delayed tasks do NOT run after `shutdown()`: the JDK default does run them, which is how a pending
     * MCP restart could fire during unload. Cancelled tasks leave the queue at once.
     */
    fun scheduled(subsystem: String): ScheduledExecutorService {
        val executor = ScheduledThreadPoolExecutor(1, factory(subsystem, numbered = false))
        executor.executeExistingDelayedTasksAfterShutdownPolicy = false
        executor.removeOnCancelPolicy = true
        return track(subsystem, executor)
    }

    /**
     * A tracked fixed pool of [size] numbered workers. Returned as a [ThreadPoolExecutor] so its owner
     * can resize it.
     */
    fun fixedPool(
        subsystem: String,
        size: Int,
    ): ThreadPoolExecutor =
        track(
            subsystem,
            ThreadPoolExecutor(size, size, 0L, TimeUnit.MILLISECONDS, LinkedBlockingQueue(), factory(subsystem)),
        )

    /** A tracked [ThreadPoolExecutor] with exactly the given arguments and numbered workers. */
    @Suppress("LongParameterList") // mirrors the ThreadPoolExecutor constructor it wraps, one to one
    fun boundedPool(
        subsystem: String,
        core: Int,
        max: Int,
        keepAlive: Long,
        unit: TimeUnit,
        queue: BlockingQueue<Runnable>,
        handler: RejectedExecutionHandler,
    ): ThreadPoolExecutor = track(subsystem, ThreadPoolExecutor(core, max, keepAlive, unit, queue, factory(subsystem), handler))

    /** Stops tracking [executor]; its owner has taken over its whole shutdown. */
    fun release(executor: ExecutorService) {
        tracked.remove(executor)
    }

    /** RED skeleton: the unload sweep lands in the GREEN commit. */
    fun terminateAll(
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
    ) {
    }

    /** A copy of the tracked pools and their subsystem labels. For tests and the unload sweep. */
    fun trackedSnapshot(): Map<ExecutorService, String> = synchronized(tracked) { LinkedHashMap(tracked) }

    private fun <E : ExecutorService> track(
        subsystem: String,
        executor: E,
    ): E {
        synchronized(tracked) {
            tracked.keys.removeAll { it.isTerminated }
            tracked[executor] = subsystem
        }
        return executor
    }

    private fun validate(subsystem: String) {
        require(subsystem.isNotBlank()) { "Thread subsystem label must not be blank (length ${subsystem.length})." }
        require(!subsystem.startsWith(ExtensionThreads.PREFIX)) {
            "Thread subsystem label must not repeat the product prefix (length ${subsystem.length})."
        }
        require(LABEL.matches(subsystem)) {
            "Thread subsystem label must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} (length ${subsystem.length})."
        }
    }

    private companion object {
        val LABEL = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
    }
}

/** The process-wide thread helper production code uses. */
internal object ExtensionThreads : ExtensionThreadPools() {
    /** Every extension thread name starts with this. */
    const val PREFIX = "burp-ai-agent-"
}
