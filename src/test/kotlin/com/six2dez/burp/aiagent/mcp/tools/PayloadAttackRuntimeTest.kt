package com.six2dez.burp.aiagent.mcp.tools

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PayloadAttackRuntimeTest {
    private fun input(mode: PayloadAttackMode = PayloadAttackMode.SNIPER) =
        IntruderAttackStart(
            "GET /?a={{a}}&b={{b}} HTTP/1.1\r\nHost: fixture.test\r\n\r\n",
            listOf(PayloadPosition("{{a}}", listOf("one", "two"), "A"), PayloadPosition("{{b}}", listOf("red", "blue"), "B")),
            "fixture.test",
            443,
            true,
            mode = mode,
            intervalMs = 0,
        )

    @Test
    fun allAttackModesExpandTheirDocumentedCombinations() {
        val sniper = PayloadAttackPlan(input())
        assertEquals(listOf(listOf("A", "B"), listOf("one", "B"), listOf("two", "B"), listOf("A", "red"), listOf("A", "blue")), (0 until sniper.total).map(sniper::values))
        val pitchfork = PayloadAttackPlan(input(PayloadAttackMode.PITCHFORK))
        assertEquals(listOf("two", "blue"), pitchfork.values(2))
        val cluster = PayloadAttackPlan(input(PayloadAttackMode.CLUSTER_BOMB))
        assertEquals(listOf(listOf("one", "red"), listOf("one", "blue"), listOf("two", "red"), listOf("two", "blue")), (1 until cluster.total).map(cluster::values))
        val ramInput = input(PayloadAttackMode.BATTERING_RAM).let { it.copy(positions = it.positions.map { p -> p.copy(payloads = listOf("x", "y")) }) }
        assertEquals(listOf("y", "y"), PayloadAttackPlan(ramInput).values(2))
    }

    @Test
    fun replacementIsLiteralNonRecursiveAndRepairsUnicodeContentLength() {
        val value = input().copy(content = "POST / HTTP/1.1\nHost: fixture.test\nContent-Length: 999\n\na={{a}}", positions = listOf(PayloadPosition("{{a}}", listOf("ёж {{a}} $1"))), includeBaseline = false)
        val rendered = PayloadAttackPlan(value).render(0)
        assertTrue(rendered.endsWith("a=ёж {{a}} $1"))
        assertTrue(rendered.contains("Content-Length: ${"a=ёж {{a}} $1".toByteArray().size}\r\n"))
    }

    @Test
    fun invalidPlansFailBeforeStartingTraffic() {
        assertThrows(IllegalArgumentException::class.java) { PayloadAttackPlan(input().copy(maxRequests = 2)) }
        assertThrows(IllegalArgumentException::class.java) { PayloadAttackPlan(input(PayloadAttackMode.BATTERING_RAM)) }
        assertThrows(IllegalArgumentException::class.java) { PayloadAttackPlan(input().copy(concurrency = 6)) }
        assertThrows(IllegalArgumentException::class.java) { PayloadAttackPlan(input().copy(positions = listOf(PayloadPosition("missing", listOf("x"))))) }
        assertThrows(IllegalArgumentException::class.java) { PayloadAttackPlan(input().copy(timeoutMs = 999)) }
    }

    @Test
    fun escapedLineBreaksAndMissingHeaderSeparatorFailBeforeAnySend() {
        val sent = AtomicInteger()
        IntruderAttackRuntime { _, _, _ ->
            sent.incrementAndGet()
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            val malformed = listOf(input().content.replace("\r\n", "\\r\\n"), "GET /?a={{a}}&b={{b}} HTTP/1.1\nHost: fixture.test\n{\"body\":true}")
            malformed.forEach { template ->
                val failure = assertThrows(IllegalArgumentException::class.java) { runtime.start(input().copy(content = template)) { } }
                assertTrue(failure.message.orEmpty().contains("Request template"))
            }
            assertEquals(0, sent.get())
        }
        assertEquals(5, PayloadAttackPlan(input().copy(content = input().content.replace("\r\n", "\n"))).total)
    }

    @Test
    fun headerOnlyTemplateMayOmitItsFinalEmptyLine() {
        val plan = PayloadAttackPlan(input().copy(content = input().content.trimEnd()))
        assertTrue(plan.render(0).endsWith("\r\n\r\n"))
        assertTrue(plan.render(0).startsWith("GET /?a=A&b=B HTTP/1.1\r\n"))
    }

    @Test
    fun scopeOfEveryRenderedRequestIsCheckedBeforeAnySend() {
        val sent = AtomicInteger()
        IntruderAttackRuntime { _, _, _ ->
            sent.incrementAndGet()
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            assertThrows(IllegalStateException::class.java) { runtime.start(input()) { if (it.contains("two")) error("out of scope") } }
            assertEquals(0, sent.get())
        }
    }

    @Test
    fun completedAttackHasPaginatedResultsAndBoundedMessages() {
        IntruderAttackRuntime { _, _, _ -> AttackHttpResult(200, 100_000, "x".repeat(100_000), "full-response-hash") }.use { runtime ->
            val id =
                runtime
                    .start(input()) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            awaitDone(runtime, id)
            val status = runtime.status(id) { _, _ -> }
            assertEquals("COMPLETED", status.getValue("state").jsonPrimitive.content)
            assertEquals("5", status.getValue("completed").jsonPrimitive.content)
            val page = runtime.results(IntruderAttackResults(id, count = 2, includeMessages = true)) { _, _ -> }
            assertEquals("2", page.getValue("nextOffset").jsonPrimitive.content)
            val row =
                page
                    .getValue("results")
                    .jsonArray
                    .first()
                    .jsonObject
            assertEquals("full-response-hash", row.getValue("responseSha256").jsonPrimitive.content)
            assertTrue(
                row
                    .getValue("response")
                    .jsonPrimitive.content.length <= ActiveToolLimits.MAX_CAPTURE_BYTES,
            )
            assertEquals("true", row.getValue("responseTruncated").jsonPrimitive.content)
            assertFalse(
                runtime
                    .results(IntruderAttackResults(id)) { _, _ -> }
                    .getValue("results")
                    .jsonArray
                    .first()
                    .jsonObject
                    .containsKey("response"),
            )
        }
    }

    @Test
    fun cancelStopsSchedulingAndKeepsResults() {
        val entered = CountDownLatch(1)
        val sent = AtomicInteger()
        IntruderAttackRuntime { _, _, _ ->
            sent.incrementAndGet()
            entered.countDown()
            Thread.sleep(20_000)
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            val id =
                runtime
                    .start(input()) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            runtime.cancel(id) { _, _ -> }
            awaitDone(runtime, id)
            assertEquals(1, sent.get())
            val gaps = runtime.results(IntruderAttackResults(id, count = 100)) { _, _ -> }
            assertTrue(gaps.getValue("pendingIndices").jsonArray.isEmpty())
            assertEquals(4, gaps.getValue("notExecutedIndices").jsonArray.size)
            assertEquals(
                "CANCELLED",
                runtime
                    .status(id) { _, _ -> }
                    .getValue("state")
                    .jsonPrimitive.content,
            )
        }
    }

    @Test
    fun concurrentCompletionDoesNotMakePaginationSkipPendingIndices() {
        val blocked = CountDownLatch(1)
        val release = CountDownLatch(1)
        IntruderAttackRuntime { raw, _, _ ->
            if (raw.contains("a=A&b=B")) {
                blocked.countDown()
                release.await(3, TimeUnit.SECONDS)
            }
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            val id =
                runtime
                    .start(input().copy(concurrency = 2)) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            assertTrue(blocked.await(2, TimeUnit.SECONDS))
            val first = runtime.results(IntruderAttackResults(id, count = 1)) { _, _ -> }
            assertEquals(listOf("0"), first.getValue("pendingIndices").jsonArray.map { it.jsonPrimitive.content })
            release.countDown()
            awaitDone(runtime, id)
            assertEquals(
                "0",
                runtime
                    .results(IntruderAttackResults(id, count = 1)) { _, _ -> }
                    .getValue("results")
                    .jsonArray
                    .first()
                    .jsonObject
                    .getValue("index")
                    .jsonPrimitive.content,
            )
        }
    }

    @Test
    fun failuresRetainOnlyExceptionTypeAndScopeCanBeRecheckedOnRead() {
        IntruderAttackRuntime { _, _, _ -> error("Authorization: secret-value") }.use { runtime ->
            val id =
                runtime
                    .start(input()) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            awaitDone(runtime, id)
            val result = runtime.results(IntruderAttackResults(id, includeMessages = true)) { _, _ -> }
            assertFalse(result.toString().contains("secret-value"))
            assertEquals(
                "FAILED",
                result
                    .getValue("status")
                    .jsonObject
                    .getValue("state")
                    .jsonPrimitive.content,
            )
            assertThrows(IllegalStateException::class.java) { runtime.status(id) { _, _ -> error("out of scope") } }
        }
    }

    @Test
    fun globalRequestConcurrencyIsBoundedAcrossJobs() {
        val current = AtomicInteger()
        val peak = AtomicInteger()
        IntruderAttackRuntime { _, _, _ ->
            val running = current.incrementAndGet()
            peak.accumulateAndGet(running, ::maxOf)
            try {
                Thread.sleep(50)
            } finally {
                current.decrementAndGet()
            }
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            val first =
                runtime
                    .start(input().copy(concurrency = 5)) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            val second =
                runtime
                    .start(input().copy(concurrency = 5)) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            awaitDone(runtime, first)
            awaitDone(runtime, second)
            assertTrue(peak.get() in 2..5)
        }
    }

    @Test
    fun totalDurationStopsFurtherSchedulingAndBoundsTransportTimeout() {
        val sent = AtomicInteger()
        IntruderAttackRuntime { _, _, timeout ->
            assertTrue(timeout in 1..1000)
            sent.incrementAndGet()
            Thread.sleep(600)
            AttackHttpResult(200, 2, "OK", "hash")
        }.use { runtime ->
            val id =
                runtime
                    .start(input().copy(durationMs = 1000)) { }
                    .getValue("attackId")
                    .jsonPrimitive.content
            awaitDone(runtime, id)
            assertEquals(
                "TIMED_OUT",
                runtime
                    .status(id) { _, _ -> }
                    .getValue("state")
                    .jsonPrimitive.content,
            )
            assertTrue(sent.get() in 1..2)
        }
    }

    private fun awaitDone(
        runtime: IntruderAttackRuntime,
        id: String,
    ) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (runtime
                .status(id) { _, _ -> }
                .getValue("inFlightWorkers")
                .jsonPrimitive.content != "0"
        ) {
            check(System.nanoTime() < until) { "Attack did not finish" }
            Thread.sleep(5)
        }
    }
}
