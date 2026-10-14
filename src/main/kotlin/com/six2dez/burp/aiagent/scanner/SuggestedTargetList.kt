package com.six2dez.burp.aiagent.scanner

import com.six2dez.burp.aiagent.util.IssueUtils
import java.util.Collections
import java.util.concurrent.atomic.AtomicLong

// AWT-free contract: MUST NOT import java.awt.* or javax.swing.*

/**
 * Phase 32 / D-06, D-07 — one target a passive finding suggests for active testing.
 *
 * [key] is the dedupe key ([SuggestedTargetList.keyOf]), [url] the request URL read once when the
 * target was added (empty when the request carries none), and [suggestedAtEpochMs] the time of the
 * first suggestion. A repeat of the same target never changes it.
 */
data class SuggestedTarget(
    val key: String,
    val target: ActiveScanTarget,
    val url: String,
    val suggestedAtEpochMs: Long,
)

/**
 * Phase 32 / D-06, D-07, D-08 — the core list of the targets passive findings suggest, in both builds.
 *
 * The passive scanner adds the suggested targets of every new finding here. The user sees them and
 * queues them by hand after a confirmation; nothing in this class sends a request or queues anything.
 *
 * - Session-only (D-06): the list lives in memory, is never persisted and never exported to MCP. It
 *   holds target URLs and parameter values. The passive scanner clears it on unload.
 * - Deduplicated (D-07): one entry per (normalized URL, injection point type, injection point name,
 *   vulnerability class). A repeat keeps the first entry, its position and its Suggested At time.
 * - Bounded (D-07): at most [cap] entries; a new entry past the cap evicts the oldest one, counts it in
 *   [droppedCount] and latches [capReached] until [clear].
 *
 * Threading: the writers are the passive scanner's worker thread and Burp's passive-scan threads; the
 * readers and removers run on the EDT. One lock guards the map, with O(1) work per entry under it and
 * no callback, logging or Swing call inside it. URLs and keys are computed before taking the lock.
 *
 * The list holds no reference to the active scanner. [version] changes once per content change, so a
 * UI refresh can skip unchanged states.
 */
class SuggestedTargetList(
    val cap: Int = DEFAULT_CAP,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val lock = Any()
    private val entries = LinkedHashMap<String, SuggestedTarget>()
    private val dropped = AtomicLong(0)

    @Volatile
    private var capHit = false

    private var changes = 0L

    init {
        require(cap > 0) { "cap must be positive: $cap" }
    }

    /**
     * Adds every target whose key is not in the list yet, in order, and returns how many were added.
     * Evicts the oldest entries while the list is over [cap].
     */
    fun addAll(targets: List<ActiveScanTarget>): Int {
        if (targets.isEmpty()) return 0
        val keyed =
            targets.map { target ->
                val url = urlOf(target)
                Triple(keyOf(url, target), url, target)
            }
        val now = clock()
        var added = 0
        synchronized(lock) {
            for ((key, url, target) in keyed) {
                if (!entries.containsKey(key)) {
                    entries[key] = SuggestedTarget(key, target, url, now)
                    added++
                    evictOverflow()
                }
            }
            if (added > 0) changes++
        }
        return added
    }

    /** The entries in insertion order, oldest first, as an immutable copy. */
    fun snapshot(): List<SuggestedTarget> = synchronized(lock) { Collections.unmodifiableList(entries.values.toList()) }

    fun count(): Int = synchronized(lock) { entries.size }

    /** True once an entry was evicted for the cap, until [clear]. */
    fun capReached(): Boolean = capHit

    /** Entries evicted for the cap since the list was created or last cleared. */
    fun droppedCount(): Long = dropped.get()

    /** Changes once per content change (add, remove, clear). */
    fun version(): Long = synchronized(lock) { changes }

    /** Removes the entries of [targets] (matched by key) and returns how many were removed. */
    fun removeAll(targets: List<ActiveScanTarget>): Int = removeKeys(targets.map { keyOf(urlOf(it), it) })

    /** Removes the entries with [keys] and returns how many were removed. */
    fun removeKeys(keys: Collection<String>): Int {
        var removed = 0
        synchronized(lock) {
            for (key in keys) {
                if (entries.remove(key) != null) removed++
            }
            if (removed > 0) changes++
        }
        return removed
    }

    /** Empties the list and resets [capReached] and [droppedCount]. */
    fun clear() {
        synchronized(lock) {
            val changed = entries.isNotEmpty() || capHit || dropped.get() > 0
            entries.clear()
            capHit = false
            dropped.set(0)
            if (changed) changes++
        }
    }

    // Called under the lock only.
    private fun evictOverflow() {
        while (entries.size > cap) {
            val eldest = entries.keys.iterator()
            eldest.next()
            eldest.remove()
            dropped.incrementAndGet()
            capHit = true
        }
    }

    companion object {
        /** D-07: the list's size limit, within the active queue's own bound of 2,000 targets. */
        const val DEFAULT_CAP = 500

        // A unit separator: it cannot appear in an enum name and does not occur in URLs or point names.
        private const val KEY_SEPARATOR = "\u001F"

        /** The dedupe key: normalized URL, injection point type and name, and vulnerability class. */
        fun keyOf(
            url: String,
            target: ActiveScanTarget,
        ): String =
            listOf(
                IssueUtils.normalizeUrl(url),
                target.injectionPoint.type.name,
                target.injectionPoint.name,
                target.vulnHint.vulnClass.name,
            ).joinToString(KEY_SEPARATOR)

        // Montoya always returns a request and a URL; a mocked request may return null for either.
        private fun urlOf(target: ActiveScanTarget): String = target.originalRequest.request()?.url() ?: ""
    }
}
