package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.SwingUtilities

/**
 * Phase 32 / D-13 — unloading the extension closes every open "AI Active Scanner Queue" dialog and
 * stops its refresh timer. The registry is driven with fakes (a JDialog cannot be built headless); the
 * dialog's own close and the MainTab call are pinned by source checks inside the right function bodies.
 */
class ActiveScanQueuePanelUnloadTest {
    private val fakes = mutableListOf<FakeDialog>()

    @AfterEach
    fun tearDown() {
        fakes.forEach { ActiveScanQueuePanel.untrack(it) }
        fakes.clear()
    }

    // --- registry ----------------------------------------------------------------------------------

    @Test
    fun disposeOnTheEdtClosesEveryTrackedDialogOnce() {
        val first = tracked()
        val second = tracked()
        assertEquals(2, ActiveScanQueuePanel.openDialogCount())

        SwingUtilities.invokeAndWait { ActiveScanQueuePanel.disposeOpenDialogs() }

        assertEquals(1, first.closes.get())
        assertEquals(1, second.closes.get())
        assertEquals(0, ActiveScanQueuePanel.openDialogCount())
        assertEquals(true, first.closedOnEdt)

        SwingUtilities.invokeAndWait { ActiveScanQueuePanel.disposeOpenDialogs() }
        assertEquals(1, first.closes.get(), "a forgotten dialog is not closed twice")
    }

    @Test
    fun disposeFromAnotherThreadClosesOnTheEdt() {
        val first = tracked()
        val second = tracked()
        assertFalse(SwingUtilities.isEventDispatchThread())

        ActiveScanQueuePanel.disposeOpenDialogs()
        SwingUtilities.invokeAndWait { } // drain the EDT

        assertEquals(1, first.closes.get())
        assertEquals(1, second.closes.get())
        assertEquals(true, first.closedOnEdt)
        assertEquals(true, second.closedOnEdt)
        assertEquals(0, ActiveScanQueuePanel.openDialogCount())
    }

    @Test
    fun anUntrackedDialogIsNotClosed() {
        val kept = tracked()
        val closedByUser = tracked()

        ActiveScanQueuePanel.untrack(closedByUser)
        SwingUtilities.invokeAndWait { ActiveScanQueuePanel.disposeOpenDialogs() }

        assertEquals(1, kept.closes.get())
        assertEquals(0, closedByUser.closes.get())
    }

    // --- wiring (source checks) --------------------------------------------------------------------

    @Test
    fun mainTabShutdownClosesTheQueueDialogs() {
        val mainTab = SourceRoots.packageFile("ui/MainTab.kt").readText(Charsets.UTF_8)
        val shutdown = bodyOf(mainTab, "fun shutdown()")

        assertTrue(shutdown.contains("ActiveScanQueuePanel.disposeOpenDialogs()"), shutdown)
        assertTrue(
            shutdown.indexOf("settingsPanel.shutdown()") < shutdown.indexOf("ActiveScanQueuePanel.disposeOpenDialogs()"),
            "closed right after the settings panel shuts down",
        )
    }

    @Test
    fun theQueueDialogClosesItselfAndItsTimerForUnload() {
        val panel = SourceRoots.packageFile("ui/panels/ActiveScanQueuePanel.kt").readText(Charsets.UTF_8)

        val declaration = panel.substring(panel.indexOf("private class QueueDialog("), panel.indexOf("Dialog.ModalityType.MODELESS"))
        assertTrue(declaration.contains("UnloadClosable"), "QueueDialog implements UnloadClosable")

        val close = bodyOf(panel, "override fun closeForUnload()")
        assertTrue(close.contains("refreshTimer.stop()"), close)
        assertTrue(close.contains("dispose()"), close)

        val show = bodyOf(panel, "fun showDialog(")
        assertTrue(show.contains("track(dialog)"), show)
        assertTrue(show.indexOf("track(dialog)") < show.indexOf("isVisible = true"), "tracked before it is shown")

        val closed = bodyOf(panel, "override fun windowClosed(")
        assertTrue(closed.contains("refreshTimer.stop()"), closed)
        assertTrue(closed.contains("untrack("), closed)
    }

    // --- helpers -----------------------------------------------------------------------------------

    private fun tracked(): FakeDialog {
        val fake = FakeDialog()
        fakes += fake
        ActiveScanQueuePanel.track(fake)
        return fake
    }

    // From the declaration to the brace that closes the first block opened after it.
    private fun bodyOf(
        source: String,
        declaration: String,
    ): String {
        val start = source.indexOf(declaration)
        assertTrue(start >= 0, "declaration not found: $declaration")
        val open = source.indexOf('{', start)
        var depth = 0
        for (i in open until source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(start, i + 1)
                }
            }
        }
        error("unbalanced braces after $declaration")
    }

    private class FakeDialog : ActiveScanQueuePanel.UnloadClosable {
        val closes = AtomicInteger()

        @Volatile
        var closedOnEdt: Boolean? = null

        override fun closeForUnload() {
            closedOnEdt = SwingUtilities.isEventDispatchThread()
            closes.incrementAndGet()
        }
    }
}
