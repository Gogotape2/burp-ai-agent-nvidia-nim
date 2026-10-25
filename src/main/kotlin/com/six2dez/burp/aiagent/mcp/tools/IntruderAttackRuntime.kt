package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.util.utf8Prefix
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

internal data class AttackHttpResult(
    val status: Int,
    val length: Int,
    val response: String,
    val responseHash: String,
)

/** Extension-owned payload runner: Montoya exposes no native Intruder attack-start API. */
internal class IntruderAttackRuntime(
    private val send: (String, IntruderAttackStart, Long) -> AttackHttpResult,
) : AutoCloseable {
    private val jobs = ConcurrentHashMap<String, Attack>()
    private val requestSlots = Semaphore(ActiveToolLimits.MAX_CONCURRENCY)
    private val closed = AtomicBoolean()

    @Synchronized
    fun start(
        input: IntruderAttackStart,
        checkScope: (String) -> Unit,
    ): JsonObject {
        check(!closed.get()) { "Active testing runtime is closed" }
        val plan = PayloadAttackPlan(input)
        // Validate every expanded URL before the first packet; headers/path can contain markers too.
        val scopeRequests =
            (0 until plan.total)
                .map { index ->
                    val rendered = plan.render(index)
                    checkScope(rendered)
                    rendered.substringBefore("\r\n") + "\r\n"
                }.distinct()
        prune()
        check(jobs.values.count { it.running.get() > 0 } < ActiveToolLimits.MAX_ACTIVE_ATTACKS) { "At most two payload attacks may run concurrently" }
        check(jobs.size < ActiveToolLimits.MAX_RETAINED_ATTACKS) { "Attack registry is full; wait for running attacks to finish" }
        val attack = Attack("attack_${UUID.randomUUID()}", plan, scopeRequests, checkScope)
        jobs[attack.id] = attack
        attack.launch()
        return attack.status()
    }

    fun status(
        id: String,
        checkScope: (IntruderAttackStart, String) -> Unit,
    ): JsonObject = find(id, checkScope).status()

    fun results(
        input: IntruderAttackResults,
        checkScope: (IntruderAttackStart, String) -> Unit,
    ): JsonObject {
        require(input.offset >= 0 && input.count in 1..ActiveToolLimits.MAX_PAGE) { "offset must be non-negative; count must be 1-100" }
        return find(input.attackId, checkScope).results(input)
    }

    fun cancel(
        id: String,
        checkScope: (IntruderAttackStart, String) -> Unit,
    ): JsonObject = find(id, checkScope).also { it.cancel() }.status()

    private fun find(
        id: String,
        checkScope: (IntruderAttackStart, String) -> Unit,
    ): Attack {
        val attack = checkNotNull(jobs[id]) { "Unknown or expired attackId" }
        attack.scopeRequests.forEach { checkScope(attack.plan.input, it) }
        return attack
    }

    private fun prune() {
        val done = jobs.values.filter { it.running.get() == 0 }.sortedBy { it.created }
        done.filter { System.currentTimeMillis() - it.created > ActiveToolLimits.RETENTION_MS }.forEach { jobs.remove(it.id, it) }
        if (jobs.size >= ActiveToolLimits.MAX_RETAINED_ATTACKS) done.firstOrNull()?.let { jobs.remove(it.id, it) }
    }

    @Synchronized
    override fun close() {
        closed.set(true)
        jobs.values.forEach { it.cancel() }
        jobs.clear()
    }

    private inner class Attack(
        val id: String,
        val plan: PayloadAttackPlan,
        val scopeRequests: List<String>,
        val checkScope: (String) -> Unit,
    ) {
        val created = System.currentTimeMillis()
        val running = AtomicInteger(plan.input.concurrency)
        private val next = AtomicInteger()
        private val cancelled = AtomicBoolean()
        private val timedOut = AtomicBoolean()
        private val completed = AtomicInteger()
        private val failures = AtomicInteger()
        private val startNanos = System.nanoTime()
        private val deadline = startNanos + TimeUnit.MILLISECONDS.toNanos(plan.input.durationMs)
        private val nextSend = AtomicLong(startNanos)
        private val results = sortedMapOf<Int, JsonObject>()
        private var storageBytes = 0
        private val threads = mutableListOf<Thread>()

        fun launch() {
            repeat(plan.input.concurrency) { n ->
                val thread = Thread({ work() }, "ai-payload-$id-$n").apply { isDaemon = true }
                threads.add(thread)
            }
            threads.forEach { it.start() }
        }

        fun cancel() {
            if (running.get() == 0) return
            cancelled.set(true)
            threads.forEach { it.interrupt() }
        }

        private fun work() {
            try {
                while (!cancelled.get() && beforeDeadline()) {
                    val index = next.getAndIncrement()
                    if (index >= plan.total || !runRequest(index)) break
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            } finally {
                running.decrementAndGet()
            }
        }

        private fun runRequest(index: Int): Boolean {
            if (!requestSlots.tryAcquire((deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS)) return false
            return try {
                pace()
                if (cancelled.get() || !beforeDeadline()) {
                    false
                } else {
                    execute(index)
                    true
                }
            } finally {
                requestSlots.release()
            }
        }

        private fun beforeDeadline(): Boolean {
            if (System.nanoTime() < deadline) return true
            timedOut.set(true)
            return false
        }

        private fun pace() {
            val interval = TimeUnit.MILLISECONDS.toNanos(plan.input.intervalMs)
            val at = nextSend.getAndUpdate { previous -> maxOf(previous, System.nanoTime()) + interval }
            val delay = minOf(at - System.nanoTime(), deadline - System.nanoTime())
            if (delay > 0) TimeUnit.NANOSECONDS.sleep(delay)
        }

        // Vendor HTTP transports may fail with arbitrary exception types; never retain their raw text.
        @Suppress("TooGenericExceptionCaught")
        private fun execute(index: Int) {
            val started = System.nanoTime()
            val request = plan.render(index)
            try {
                checkScope(request)
                val remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()).coerceAtLeast(1)
                val response = send(request, plan.input, minOf(plan.input.timeoutMs, remaining))
                save(index, request, response, elapsedMs(started), null)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                cancelled.set(true)
                failures.incrementAndGet()
                save(index, request, null, elapsedMs(started), e.javaClass.simpleName)
            } catch (e: Exception) {
                failures.incrementAndGet()
                // Provider/target exception text can contain request credentials; retain only its type.
                save(index, request, null, elapsedMs(started), e.javaClass.simpleName)
            } finally {
                completed.incrementAndGet()
            }
        }

        @Synchronized
        private fun save(
            index: Int,
            request: String,
            response: AttackHttpResult?,
            elapsedMs: Long,
            error: String?,
        ) {
            val remaining = (ActiveToolLimits.ATTACK_STORAGE_BYTES - storageBytes).coerceAtLeast(0)
            val requestCapture = utf8Prefix(request, minOf(ActiveToolLimits.MAX_CAPTURE_BYTES, remaining / 2))
            val responseCapture = utf8Prefix(response?.response.orEmpty(), minOf(ActiveToolLimits.MAX_CAPTURE_BYTES, remaining / 2))
            storageBytes += requestCapture.toByteArray().size + responseCapture.toByteArray().size
            results[index] =
                buildJsonObject {
                    put("index", index)
                    put("baseline", plan.input.includeBaseline && index == 0)
                    put("payloadPreviews", JsonArray(plan.values(index).map { JsonPrimitive(utf8Prefix(it, ActiveToolLimits.PAYLOAD_PREVIEW_BYTES)) }))
                    put("elapsedMs", elapsedMs)
                    response?.let {
                        put("statusCode", it.status)
                        put("responseBytes", it.length)
                        put("responseSha256", it.responseHash)
                    }
                    error?.let { put("errorClass", it) }
                    put("request", requestCapture)
                    put("response", responseCapture)
                    put("requestTruncated", requestCapture != request)
                    put("responseTruncated", responseCapture.toByteArray().size < (response?.length ?: 0))
                }
        }

        fun status(): JsonObject =
            buildJsonObject {
                put("attackId", id)
                put("engine", "extension-http-payload-runner")
                put("mode", plan.input.mode.name)
                put("concurrency", plan.input.concurrency)
                put("intervalMs", plan.input.intervalMs)
                put(
                    "state",
                    when {
                        running.get() > 0 -> if (cancelled.get()) "CANCELLING" else "RUNNING"
                        cancelled.get() -> "CANCELLED"
                        timedOut.get() -> "TIMED_OUT"
                        failures.get() == completed.get() -> "FAILED"
                        else -> "COMPLETED"
                    },
                )
                put("planned", plan.total)
                put("completed", completed.get())
                put("failed", failures.get())
                put("inFlightWorkers", running.get())
                put("elapsedMs", elapsedMs(startNanos))
            }

        @Synchronized
        fun results(input: IntruderAttackResults): JsonObject {
            // Offset is a request index, not completion order: a slow earlier result cannot be skipped.
            val end = minOf(input.offset.toLong() + input.count, plan.total.toLong()).toInt()
            val rows =
                (input.offset until end).mapNotNull { results[it] }.map {
                    if (input.includeMessages) it else JsonObject(it - setOf("request", "response"))
                }
            val pending = (input.offset until end).filter { !results.containsKey(it) }
            return buildJsonObject {
                put("status", status())
                put("results", JsonArray(rows))
                put("pendingIndices", JsonArray(if (running.get() > 0) pending.map(::JsonPrimitive) else emptyList()))
                put("notExecutedIndices", JsonArray(if (running.get() == 0) pending.map(::JsonPrimitive) else emptyList()))
                if (end < plan.total) put("nextOffset", end)
                put("note", "Revisit pendingIndices while the job runs. notExecutedIndices are terminal gaps: do not keep polling them. Messages are bounded captures, not complete evidence when truncated.")
            }
        }
    }
}

private fun elapsedMs(started: Long) = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
