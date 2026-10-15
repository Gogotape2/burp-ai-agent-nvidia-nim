package com.six2dez.burp.aiagent.ui

import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertTimeoutPreemptively
import org.mockito.kotlin.mock
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

/**
 * EDT-01 / SC5 (Phase 33): acting on a site-map subtree must not walk the site map on the EDT.
 *
 * BApp #231 finding 1 already made the walk lazy, so building the context menu is cheap. The walk itself
 * (`api.siteMap().requestResponses(filter)`, which iterates the WHOLE site map) still ran inside each
 * action listener, on the EDT, and froze Burp on a large project. [SiteMapSubtreeTargets] marks a
 * resolution as that walk, and [ContextTargetResolver.resolve] runs it on the daemon thread
 * `burp-ai-agent-sitemap-resolve`, then continues on the EDT with the resolved list, so every dialog
 * (and every count a dialog shows) still happens on the EDT and uses the real list.
 *
 * MainTab is not headless-constructible yet (plan 33-09), so the behavioural cases drive the resolver
 * directly; the structural case reads UiActions.kt to prove every action goes through it.
 *
 * Every timeout here is a deadlock failsafe, never a threshold the work is measured against.
 */
class SiteMapResolveOffEdtTest {
    private val dispatched = CopyOnWriteArrayList<String>()

    @BeforeEach
    fun installObservers() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver { label -> dispatched.add(label) }
    }

    @AfterEach
    fun releaseObservers() {
        OffEdtDispatch.registerSettledObserver(null)
        OffEdtDispatch.registerDispatchedObserver(null)
    }

    @Test
    fun aSiteMapSubtreeIsWalkedOffTheEdtWhileTheEdtStaysFreeAndTheActionContinuesOnTheEdt() {
        val first = mock<HttpRequestResponse>()
        val second = mock<HttpRequestResponse>()
        val walkOnEdt = AtomicReference<Boolean?>(null)
        val walkThread = AtomicReference<String?>(null)
        val walkStarted = CountDownLatch(1)
        val release = CountDownLatch(1)
        val resolvedOnEdt = AtomicReference<Boolean?>(null)
        val resolvedList = AtomicReference<List<HttpRequestResponse>?>(null)
        val resolved = CountDownLatch(1)
        val resolvedBeforeReturn = AtomicBoolean(true)

        val targets =
            SiteMapSubtreeTargets({ }) {
                walkOnEdt.set(SwingUtilities.isEventDispatchThread())
                walkThread.set(Thread.currentThread().name)
                walkStarted.countDown()
                release.await(FAILSAFE_SECONDS, TimeUnit.SECONDS)
                listOf(first, second)
            }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            SwingUtilities.invokeAndWait {
                ContextTargetResolver.resolve(targets, null) { list ->
                    resolvedOnEdt.set(SwingUtilities.isEventDispatchThread())
                    resolvedList.set(list)
                    resolved.countDown()
                }
                resolvedBeforeReturn.set(resolved.count == 0L)
            }
            assertFalse(resolvedBeforeReturn.get(), "resolve must return on the EDT before a site-map walk finishes")
            assertTrue(walkStarted.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the site-map walk never started")

            val probe = CountDownLatch(1)
            SwingUtilities.invokeLater { probe.countDown() }
            assertTrue(
                probe.await(FAILSAFE_SECONDS, TimeUnit.SECONDS),
                "EDT-01: the EDT must stay free while the site map is walked",
            )
            assertEquals(1L, resolved.count, "the action must not continue before the walk returns")

            release.countDown()
            assertTrue(resolved.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the action never continued with the list")
            SwingUtilities.invokeAndWait { }
        }

        assertEquals(false, walkOnEdt.get(), "EDT-01: the site-map walk ran on the EDT")
        assertEquals(SITEMAP_THREAD, walkThread.get(), "the walk must run on the named sitemap-resolve worker")
        assertEquals(true, resolvedOnEdt.get(), "the action must continue on the EDT, where its dialogs live")
        assertEquals(listOf(first, second), resolvedList.get())
        assertEquals(listOf(SITEMAP_LABEL), dispatched.toList())
    }

    @Test
    fun anAlreadyResolvedSubtreeContinuesInlineWithoutASecondWalk() {
        val rr = mock<HttpRequestResponse>()
        val walks = AtomicInteger(0)
        val targets =
            SiteMapSubtreeTargets({ }) {
                walks.incrementAndGet()
                listOf(rr)
            }
        val firstResolved = CountDownLatch(1)

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            SwingUtilities.invokeAndWait { ContextTargetResolver.resolve(targets, null) { firstResolved.countDown() } }
            assertTrue(firstResolved.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the first resolution never continued")
            SwingUtilities.invokeAndWait { }
        }
        dispatched.clear()

        val inline = AtomicReference<List<HttpRequestResponse>?>(null)
        val onEdt = AtomicReference<Boolean?>(null)
        SwingUtilities.invokeAndWait {
            ContextTargetResolver.resolve(targets, null) { list ->
                onEdt.set(SwingUtilities.isEventDispatchThread())
                inline.set(list)
            }
            assertEquals(listOf(rr), inline.get(), "a resolved subtree must continue before resolve returns")
        }

        assertEquals(true, onEdt.get())
        assertEquals(1, walks.get(), "the site map must be walked once per menu, not once per action")
        assertTrue(dispatched.isEmpty(), "no worker may start for an already resolved subtree: $dispatched")
    }

    @Test
    fun aSelectionThatIsNotASubtreeResolvesInlineOnTheEdt() {
        val rr = mock<HttpRequestResponse>()
        val inline = AtomicReference<List<HttpRequestResponse>?>(null)
        val onEdt = AtomicReference<Boolean?>(null)

        SwingUtilities.invokeAndWait {
            ContextTargetResolver.resolve(lazy { listOf(rr) }, null) { list ->
                onEdt.set(SwingUtilities.isEventDispatchThread())
                inline.set(list)
            }
            assertEquals(listOf(rr), inline.get(), "selected messages must resolve inline, with no thread hop")
        }

        assertEquals(true, onEdt.get())
        assertTrue(dispatched.isEmpty(), "no worker may start for a plain selection: $dispatched")
    }

    @Test
    fun aWalkThatThrowsIsLoggedOnceAndTheActionStops() {
        val log = CopyOnWriteArrayList<String>()
        val settled = CountDownLatch(1)
        val continued = AtomicBoolean(false)
        OffEdtDispatch.registerSettledObserver { label -> if (label == SITEMAP_LABEL) settled.countDown() }
        val targets = SiteMapSubtreeTargets({ line -> log.add(line) }) { throw IllegalStateException(WALK_FAILURE) }

        assertTimeoutPreemptively(Duration.ofSeconds(30)) {
            SwingUtilities.invokeAndWait { ContextTargetResolver.resolve(targets, null) { continued.set(true) } }
            assertTrue(settled.await(FAILSAFE_SECONDS, TimeUnit.SECONDS), "the failed walk never reached its EDT tail")
        }

        val walkFailures = log.filter { it.startsWith("[OffEdtDispatch] $SITEMAP_LABEL failed off the EDT: ") }
        assertEquals(1, walkFailures.size, "a failed walk must be logged exactly once: $log")
        assertTrue(walkFailures.single().contains(WALK_FAILURE))
        assertFalse(continued.get(), "the action must stop when the site map could not be read")
        assertFalse(targets.isInitialized(), "a failed walk must not be memoized as a result")
    }

    @Test
    fun uiActionsReadsEveryTargetListThroughTheResolver() {
        val source = SourceRoots.packageFile("ui/UiActions.kt").readText(Charsets.UTF_8)
        val code =
            source
                .lines()
                .filterNot { line ->
                    val trimmed = line.trimStart()
                    trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
                }.joinToString("\n")

        assertFalse(code.contains("targets.value"), "UiActions must not read a targets lazy directly on the EDT")
        assertEquals(1, Regex(Regex.escape("SiteMapSubtreeTargets(")).findAll(code).count(), "the subtree marker is built once")
        assertTrue(code.contains("ContextTargetResolver.resolve("), "actions must resolve their targets through the resolver")
        listOf(
            "= ActiveScanPrompts.ensureActiveScannerEnabled(tab.root, activeAiScanner)",
            "ActiveScanPrompts.confirmActiveScan(",
            "ManualScanDialogs.confirmActiveScanMessage(",
            "ManualScanDialogs.hostCount(",
        ).forEach { pin -> assertTrue(source.contains(pin), "SuggestedQueueDialogTest pin lost: $pin") }
    }
}

/** Deadlock failsafe, in seconds; nothing here compares an elapsed duration to it. */
private const val FAILSAFE_SECONDS = 10L

private const val SITEMAP_THREAD = "burp-ai-agent-sitemap-resolve"

private const val SITEMAP_LABEL = "site map subtree"

private const val WALK_FAILURE = "EDT-01 probe: the site map walk exploded"
