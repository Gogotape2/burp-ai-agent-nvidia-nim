package com.six2dez.burp.aiagent.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Phase 32 / D-06, D-07 — the contract of the core suggested-target list: deduplicated on (normalized
 * URL, injection point type, injection point name, vulnerability class), bounded with drop-oldest,
 * safe under concurrent writers and an EDT-style reader, and session-only (no persistence API in the
 * file, no MCP reader).
 */
class SuggestedTargetListTest {
    @Test
    fun targetsWithTheSameNormalizedUrlPointAndClassMakeOneEntry() {
        val list = SuggestedTargetList()
        // normalizeUrl drops the query and folds numeric ids of two or more digits into {id}.
        val first = target("https://h1.example/users/12?x=1")
        val sameKey = target("https://h1.example/users/34?x=2")

        assertEquals(1, list.addAll(listOf(first)))
        assertEquals(0, list.addAll(listOf(sameKey)), "the same normalized URL, point and class is a repeat")
        assertEquals(1, list.count())
        assertEquals(SuggestedTargetList.keyOf("https://h1.example/users/12", first), SuggestedTargetList.keyOf("https://h1.example/users/34", sameKey))

        val otherHost = target("https://h2.example/users/12?x=1")
        val otherPoint = target("https://h1.example/users/12", name = "other")
        val otherType = target("https://h1.example/users/12", type = InjectionType.BODY_PARAM)
        val otherClass = target("https://h1.example/users/12", vulnClass = VulnClass.XSS_REFLECTED)

        assertEquals(4, list.addAll(listOf(otherHost, otherPoint, otherType, otherClass)))
        assertEquals(5, list.count(), "a second host, point name, point type or class is a separate entry")
    }

    @Test
    fun aRepeatKeepsTheFirstTimePositionCountAndVersion() {
        val ticks = AtomicLong(0)
        val list = SuggestedTargetList { ticks.incrementAndGet() }
        val a = target("https://repeat.example/a")
        val b = target("https://repeat.example/b")
        list.addAll(listOf(a))
        list.addAll(listOf(b))
        val countBefore = list.count()
        val versionBefore = list.version()

        assertEquals(0, list.addAll(listOf(target("https://repeat.example/a"))))

        val entries = list.snapshot()
        assertEquals(listOf("https://repeat.example/a", "https://repeat.example/b"), entries.map { it.url }, "the repeat keeps its position")
        assertEquals(1L, entries.first().suggestedAtEpochMs, "the repeat keeps the first Suggested At time")
        assertEquals(countBefore, list.count())
        assertEquals(versionBefore, list.version(), "a repeat is not a content change")
    }

    @Test
    fun theCapDropsTheOldestCountsDropsAndLatchesUntilClear() {
        val list = SuggestedTargetList(cap = 3)
        val targets = (1..5).map { target("https://cap.example/p$it") }

        list.addAll(targets)

        assertEquals(targets.takeLast(3).map { it.originalRequest.request().url() }, list.snapshot().map { it.url })
        assertEquals(2L, list.droppedCount())
        assertTrue(list.capReached())

        list.clear()

        assertEquals(0, list.count())
        assertEquals(0L, list.droppedCount(), "clear resets the dropped count")
        assertFalse(list.capReached(), "clear resets the cap flag")
    }

    /** 32-REVIEW WR-01 / D-06: the unload clear empties the list and refuses every later add. */
    @Test
    fun theUnloadClearEmptiesTheListAndRefusesLaterAdds() {
        val list = SuggestedTargetList()
        list.addAll(listOf(target("https://latch.example/a"), target("https://latch.example/b")))

        list.clear(refuseLaterAdds = true)
        assertEquals(0, list.count())
        val versionAfterClear = list.version()

        assertEquals(0, list.addAll(listOf(target("https://latch.example/late"))), "a refused add reports nothing added")
        assertEquals(0, list.count(), "nothing lands after the unload clear")
        assertEquals(versionAfterClear, list.version(), "a refused add is not a content change")
    }

    /** "Clear suggestions" uses the plain clear: the list stays open for later findings. */
    @Test
    fun thePlainClearLeavesTheListOpen() {
        val list = SuggestedTargetList()
        list.addAll(listOf(target("https://open.example/a")))

        list.clear()

        assertEquals(2, list.addAll(listOf(target("https://open.example/b"), target("https://open.example/c"))))
        assertEquals(2, list.count())
    }

    @Test
    fun theUnloadClearOnAnEmptyListStillRefusesLaterAdds() {
        val list = SuggestedTargetList()

        list.clear(refuseLaterAdds = true)

        assertEquals(0, list.addAll(listOf(target("https://empty-latch.example/a"))))
        assertEquals(0, list.count())
    }

    @Test
    fun theDefaultListStopsAtFiveHundred() {
        assertEquals(500, SuggestedTargetList.DEFAULT_CAP)
        val list = SuggestedTargetList()

        list.addAll((1..DEFAULT_CAP_PLUS_ONE).map { target("https://default-cap.example/p$it") })

        assertEquals(SuggestedTargetList.DEFAULT_CAP, list.count())
        assertEquals(1L, list.droppedCount())
        assertTrue(list.capReached())
    }

    @Test
    fun concurrentWritersAndAReaderNeverThrowAndRespectTheCap() {
        val list = SuggestedTargetList()
        val batches =
            (0 until WRITERS).map { writer ->
                (0 until PER_WRITER).map { target("https://concurrent.example/w$writer/t$it") }.chunked(BATCH)
            }
        val start = CountDownLatch(1)
        val failures: MutableList<Throwable> = Collections.synchronizedList(mutableListOf())
        val writersDone = AtomicBoolean(false)
        val writers =
            batches.map { writerBatches ->
                Thread {
                    runCatching {
                        start.await()
                        writerBatches.forEach { list.addAll(it) }
                    }.onFailure { failures += it }
                }
            }
        val reader =
            Thread {
                runCatching {
                    start.await()
                    while (!writersDone.get()) {
                        list.snapshot()
                        list.count()
                    }
                }.onFailure { failures += it }
            }
        (writers + reader).forEach { it.start() }

        start.countDown()
        writers.forEach { it.join(JOIN_MILLIS) }
        writersDone.set(true)
        reader.join(JOIN_MILLIS)

        assertTrue((writers + reader).none { it.isAlive }, "a thread is stuck: possible deadlock")
        assertEquals(emptyList<Throwable>(), failures.toList())
        assertEquals(SuggestedTargetList.DEFAULT_CAP, list.count())
        assertEquals((WRITERS * PER_WRITER - SuggestedTargetList.DEFAULT_CAP).toLong(), list.droppedCount())
        val keys = list.snapshot().map { it.key }
        assertEquals(keys.size, keys.toSet().size, "the snapshot keys are distinct")
    }

    @Test
    fun removeAndVersionFollowEveryContentChangeExactlyOnce() {
        val list = SuggestedTargetList()
        val a = target("https://remove.example/a")
        val b = target("https://remove.example/b")
        val c = target("https://remove.example/c")
        val v0 = list.version()

        assertEquals(0, list.addAll(emptyList()))
        assertEquals(v0, list.version(), "an empty add changes nothing")

        list.addAll(listOf(a, b, c))
        val v1 = list.version()
        assertEquals(v0 + 1, v1, "one add of three entries is one change")

        assertEquals(2, list.removeAll(listOf(a, b)))
        assertEquals(listOf("https://remove.example/c"), list.snapshot().map { it.url })
        val v2 = list.version()
        assertEquals(v1 + 1, v2)

        assertEquals(0, list.removeKeys(listOf("absent")))
        assertEquals(v2, list.version(), "removing an absent key is not a change")

        list.clear()
        assertEquals(v2 + 1, list.version())
        list.clear()
        assertEquals(v2 + 1, list.version(), "clearing an empty list is not a change")
    }

    @Test
    fun aTargetWithANullUrlIsAddedUnderAnEmptyUrlKey() {
        val list = SuggestedTargetList()
        val noUrl = target(null)

        assertEquals(1, list.addAll(listOf(noUrl)))

        val entry = list.snapshot().single()
        assertEquals("", entry.url)
        assertEquals(SuggestedTargetList.keyOf("", noUrl), entry.key)
    }

    @Test
    fun theListIsSessionOnlyAndNotExportedToMcp() {
        val source = SourceRoots.packageFile("scanner/SuggestedTargetList.kt").readText(Charsets.UTF_8)
        val persistenceHits = PERSISTENCE_TOKENS.filter { it in source }
        assertEquals(emptyList<String>(), persistenceHits, "SuggestedTargetList.kt names a persistence API")

        val files = SourceRoots.kotlinFiles()
        assertTrue(files.size >= MIN_EXPECTED_MAIN_FILES, "walked ${files.size} production files, below the floor of $MIN_EXPECTED_MAIN_FILES")
        val mcpFiles = files.filter { SourceRoots.packageRelativePath(it).startsWith("mcp/") }
        assertTrue(mcpFiles.isNotEmpty(), "the walk reached no mcp/ file")
        val readers =
            mcpFiles
                .filter { "suggestedTargets" in it.readText(Charsets.UTF_8) }
                .map { SourceRoots.relativePath(it) }
        assertEquals(emptyList<String>(), readers, "an MCP file reads the suggested-target list")
    }

    private fun target(
        url: String?,
        type: InjectionType = InjectionType.URL_PARAM,
        name: String = "id",
        vulnClass: VulnClass = VulnClass.SQLI,
    ): ActiveScanTarget {
        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        val requestResponse = mock<HttpRequestResponse>()
        whenever(requestResponse.request()).thenReturn(request)
        return ActiveScanTarget(
            originalRequest = requestResponse,
            injectionPoint = InjectionPoint(type, name, "v"),
            vulnHint = VulnHint(vulnClass, 90, "evidence"),
        )
    }

    private companion object {
        const val DEFAULT_CAP_PLUS_ONE = 501
        const val WRITERS = 8
        const val PER_WRITER = 200
        const val BATCH = 10
        const val JOIN_MILLIS = 30_000L
        const val MIN_EXPECTED_MAIN_FILES = 150
        val PERSISTENCE_TOKENS = listOf("persistence(", "Preferences", "java.io.File", "Files.", "ObjectOutputStream")
    }
}
