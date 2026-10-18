package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.util.ExtensionThreads
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * REL-07 / SC5 — the live-file registry for CLI subprocess temp files, plus the single JVM exit hook
 * that sweeps it (CONTEXT.md D-01 through D-04).
 *
 * It replaces the JDK's `File.deleteOnExit()` facility, which `CliBackend` used to call once per CLI
 * invocation. That facility keeps its registrations in a static set with no removal API, so every
 * invocation retained one path string for the life of the Burp JVM — growth bounded by lifetime
 * invocation count, which is unbounded in a long session (threat T-24-15).
 *
 * Guarantees:
 *  - `CliBackend`'s `finally` block remains the PRIMARY cleanup path for both temp files, on the
 *    normal path and on the exception path. It deletes each file and clears its entry here. This
 *    object changes nothing about that; it is a genuine safety net, not a replacement.
 *  - The one case the net uniquely covers is a clean Burp quit while a CLI call is in flight: the
 *    `finally` has not run yet, and the JVM exit hook armed here deletes what is still registered.
 *  - [drain] and the `finally` block may both run for the same file. A double delete is expected and
 *    must never surface as an error.
 *
 * Bound:
 *  The set holds at most one entry per IN-FLIGHT CLI call — normally zero or one, since a CLI call
 *  creates at most one prompt file and at most one codex output file and both are deregistered when
 *  the call ends. The bound is therefore concurrency, not lifetime invocation count. That is the whole
 *  of D-01's argument: the same crash-time coverage, with a set that returns to empty.
 *
 * Window NOT closed:
 *  A registry that lives in JVM memory cannot reap a file orphaned by SIGKILL or by power loss,
 *  because on those paths neither the `finally` block nor any exit hook runs (D-04, threat T-24-06).
 *  The residual is at most one temp file per in-flight call, left in the OS temp directory, which the
 *  OS reaps on its own schedule; the prompt file also keeps its owner-only POSIX permissions, which is
 *  the compensating control. A bounded prefix sweep at extension load was considered and rejected in
 *  D-04, because a second concurrent Burp instance can legitimately own live files under the same
 *  prefixes. Separately: entries the JDK facility already accumulated inside a Burp process that is
 *  running right now cannot be undone by this change — SC5 is about future invocations — so inspecting
 *  a long-running Burp session is not a way to verify this fix.
 *
 * Why the hook must be removed on unload:
 *  The hook armed here is a class loaded by the extension's own classloader, so a hook that is never
 *  unregistered pins a dead classloader on every extension reload, and re-arms a second one on the
 *  next load (threat T-24-07). This is a property of THIS hook specifically, and not of the JDK
 *  facility being removed, which retained plain path strings and pinned nothing. [shutdown] is called
 *  from `App.shutdown()` through the "Backend registry" step (`BackendRegistry.shutdown()` runs
 *  `CliBackend.shutdown()`), which is also the only thing that covers a CLI call still in flight when the
 *  extension is unloaded while Burp keeps running — the JVM exit hook does not fire on unload.
 *
 * Visibility: `internal` so `CliBackendTempFileTest` can drive every path in pure JVM without a
 * subprocess and without reflecting into `java.base`. That assertability is the reason D-02 put the
 * registry in its own file rather than in a private companion inside `CliBackend`. Not part of the
 * backend's public surface.
 */
internal object CliTempFileRegistry {
    /** Absolute paths of temp files belonging to CLI calls that are still in flight. */
    private val liveFiles: MutableSet<String> = ConcurrentHashMap.newKeySet()

    private val hookLock = Any()

    /** The single exit hook, armed lazily on the first [register] and dropped by [shutdown]. */
    private var hook: Thread? = null

    /**
     * Records [file] as belonging to an in-flight CLI call and arms the exit hook if it is not armed
     * yet. Arming is lazy by requirement (D-03), not as an optimisation: a Burp session that never uses
     * a CLI backend must pay nothing — no hook object and no extension-classloader class held by the
     * JVM's exit-hook table.
     */
    fun register(file: File) {
        liveFiles.add(file.absolutePath)
        armHook()
    }

    /**
     * Drops [file]'s entry. Safe for a path that was never registered: `CliBackend`'s `finally` block
     * runs on paths where the optional prompt or codex output file was never created.
     */
    fun deregister(file: File) {
        liveFiles.remove(file.absolutePath)
    }

    /**
     * Deletes [file] and drops its entry, but drops the entry only once the file is actually gone.
     *
     * `File.delete()` reports failure by returning `false`, not by throwing: on Windows it returns
     * `false` while the CLI child process still holds the handle open. An unconditional deregister
     * therefore abandons such a file — it is off the disk's cleanup path and off this registry at the
     * same time, so neither the exit hook nor [shutdown]'s drain can ever sweep it. Keeping the entry
     * is what lets the drain retry, and it is the coverage the JDK exit-time facility used to provide
     * for this exact case.
     *
     * A `null` [file] is a no-op: `CliBackend`'s `finally` block runs on paths where the optional
     * prompt file or codex output file was never created. Nothing is caught here. A `SecurityException`
     * from `delete()` propagates to the caller's own cleanup catch and leaves the entry in place, which
     * is the same conservative outcome as a `false` return.
     */
    fun deleteAndDeregister(file: File?) {
        if (file == null) return
        if (file.delete() || !file.exists()) {
            deregister(file)
        }
    }

    /**
     * Deletes every still-registered file and empties the registry.
     *
     * Idempotent with the `finally` block by requirement (D-03): a file the `finally` already deleted
     * simply fails to delete again, and that is not an error.
     */
    fun drain() {
        val snapshot = liveFiles.toList()
        liveFiles.clear()
        snapshot.forEach { path ->
            try {
                File(path).delete()
            } catch (_: Exception) {
                // INTENTIONAL: cleanup sweep; both this drain and CliBackend's finally block legitimately
                // run for the same file, and one file's failure must not stop the rest of the sweep.
            }
        }
    }

    /**
     * Unregisters the exit hook and drains the registry. Called on extension unload through
     * `CliBackend.shutdown()`, which `BackendRegistry.shutdown()` runs for each of the five CLI backends.
     *
     * Idempotent: calling it twice, or calling it in a session that never armed a hook, does nothing.
     * No catch is hand-rolled around the unregistration — the JVM's hook-removal call throws
     * `IllegalStateException` when the VM is already shutting down, and `BackendRegistry.shutdown()`
     * catches each backend's throw so the other backends still shut down, inside App's
     * "Backend registry" safeShutdownStep (threat T-24-16). In that case the hook itself performs the drain.
     */
    fun shutdown() {
        val armed =
            synchronized(hookLock) {
                val current = hook
                hook = null
                current
            }
        if (armed != null) {
            Runtime.getRuntime().removeShutdownHook(armed)
        }
        drain()
    }

    /** Number of files currently attributed to in-flight CLI calls. Test seam. */
    internal fun sizeForTests(): Int = liveFiles.size

    /** Whether the exit hook is currently armed. Test seam for D-03's laziness and removal. */
    internal fun isHookRegisteredForTests(): Boolean = synchronized(hookLock) { hook != null }

    /** The armed exit hook, or null. Test seam for its thread name (Phase 33 D-11). */
    internal fun hookThreadForTests(): Thread? = synchronized(hookLock) { hook }

    /**
     * Returns the object to a known state without deleting anything. Test seam.
     *
     * It deliberately does NOT unregister an already-armed hook, so a suite that arms one must call
     * [shutdown] to leave the JVM clean.
     */
    internal fun resetForTests() {
        liveFiles.clear()
        synchronized(hookLock) { hook = null }
    }

    private fun armHook() {
        synchronized(hookLock) {
            if (hook != null) return
            val thread = ExtensionThreads.newThread("cli-temp-sweep") { drain() }
            Runtime.getRuntime().addShutdownHook(thread)
            hook = thread
        }
    }
}
