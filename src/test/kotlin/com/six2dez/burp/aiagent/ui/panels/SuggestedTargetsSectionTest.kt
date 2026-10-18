package com.six2dez.burp.aiagent.ui.panels

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.six2dez.burp.aiagent.SourceRoots
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.SuggestedTarget
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.swing.JComponent
import javax.swing.RowSorter
import javax.swing.SortOrder
import javax.swing.SwingUtilities

/**
 * Phase 32 / D-01, D-03, D-05, D-08 — the Suggested section of the "AI Active Scanner Queue" dialog:
 * its columns, its plain-text cells (research Pitfall 7), its three buttons, its version-gated refresh
 * and its selection kept by key across refreshes (Pitfall 8). Every Swing component is built and
 * clicked on the EDT; the dialog itself cannot be built headless, so its wiring is pinned by source checks.
 */
class SuggestedTargetsSectionTest {
    private val formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    // --- columns and rows --------------------------------------------------------------------------

    @Test
    fun columnsAreExactlyTheD03Columns() {
        val model = SuggestedTargetsTableModel(formatter)

        assertEquals(
            listOf("Suggested At", "Vulnerability", "Injection Point", "URL", "Confidence"),
            (0 until model.columnCount).map { model.getColumnName(it) },
        )
    }

    @Test
    fun rowsShowClassPointUrlAndConfidenceButNeverTheOriginalValue() {
        val list = threeTargets()
        onEdt {
            val section = SuggestedTargetsSection(list, {}, formatter)
            assertTrue(section.refreshIfChanged(), "the first refresh loads the rows")
            assertEquals(3, section.table.rowCount)

            val rows = (0 until section.table.model.rowCount).map { row -> cellsOf(section, row) }
            assertTrue(
                rows.contains(listOf("SQLI", "URL_PARAM:id", URL_ITEMS, "90%")),
                "rows: $rows",
            )
            assertTrue(rows.contains(listOf("IDOR", "COOKIE:session", URL_ACCOUNT, "60%")), "rows: $rows")
            val allCells =
                (0 until section.table.model.rowCount).flatMap { row ->
                    (0 until section.table.model.columnCount).map { col -> cellText(section, row, col) }
                }
            assertFalse(allCells.any { it.contains(COOKIE_VALUE) }, "the cookie value must never be shown: $allCells")
            assertEquals("1970-01-01 00:00:01", section.table.model.getValueAt(0, 0))

            assertFalse(section.refreshIfChanged(), "no list change, no reload")
        }
    }

    // --- renderer ----------------------------------------------------------------------------------

    @Test
    fun anHtmlUrlRendersAsPlainText() {
        val list = SuggestedTargetList().also { it.addAll(listOf(target("<html><b>x</b>", "id", InjectionType.URL_PARAM, "1"))) }
        onEdt {
            val section = SuggestedTargetsSection(list, {}, formatter)
            section.refreshNow()
            val table = section.table

            val component = table.prepareRenderer(table.getCellRenderer(0, 3), 0, 3)

            assertTrue(component is JComponent, "renderer component: $component")
            component as JComponent
            assertEquals(true, component.getClientProperty("html.disable"))
            assertNull(component.getClientProperty("html"), "no HTML view may be built for target text")
        }
    }

    @Test
    fun theRendererDisablesHtmlOnItsOwn() {
        onEdt {
            assertEquals(true, PlainTextTableCellRenderer().getClientProperty("html.disable"))
        }
    }

    // --- buttons -----------------------------------------------------------------------------------

    @Test
    fun queueAllLabelsAndEnabledStatesFollowTheCount() {
        assertEquals("Queue 1 suggested target", queueAllLabel(1))
        assertEquals("Queue 3 suggested targets", queueAllLabel(3))
        assertEquals("Queue 0 suggested targets", queueAllLabel(0))

        onEdt {
            val empty = SuggestedTargetsSection(SuggestedTargetList(), {}, formatter)
            empty.refreshNow()
            assertEquals("Queue 0 suggested targets", empty.queueAllButton.text)
            assertFalse(empty.queueAllButton.isEnabled)
            assertFalse(empty.clearButton.isEnabled)
            assertEquals("Queue selected", empty.queueSelectedButton.text)
            assertEquals("Clear suggestions", empty.clearButton.text)

            val one = SuggestedTargetList().also { it.addAll(listOf(target(URL_ITEMS, "id", InjectionType.URL_PARAM, "1"))) }
            val single = SuggestedTargetsSection(one, {}, formatter)
            single.refreshNow()
            assertEquals("Queue 1 suggested target", single.queueAllButton.text)

            val three = SuggestedTargetsSection(threeTargets(), {}, formatter)
            three.refreshNow()
            assertEquals("Queue 3 suggested targets", three.queueAllButton.text)
            assertTrue(three.queueAllButton.isEnabled)
            assertTrue(three.clearButton.isEnabled)
        }
    }

    @Test
    fun queueAllHandsEveryEntryInListOrderToTheFlow() {
        val list = threeTargets()
        val calls = mutableListOf<List<SuggestedTarget>>()
        onEdt {
            val section = SuggestedTargetsSection(list, { calls += it }, formatter)
            section.refreshNow()

            section.queueAllButton.doClick()
        }

        assertEquals(1, calls.size)
        assertEquals(list.snapshot().map { it.key }, calls.single().map { it.key })
        assertEquals(3, list.count(), "the section itself queues and removes nothing")
    }

    /**
     * 32-REVIEW WR-02 / D-05: "Queue N suggested targets" hands over exactly the N rows the table shows,
     * never an entry added to the list since the last refresh; after a refresh it shows and hands over all.
     */
    @Test
    fun queueAllHandsOverOnlyTheDisplayedRows() {
        val list = threeTargets()
        val late = target("https://late.example/x", "q", InjectionType.URL_PARAM, "1")
        val calls = mutableListOf<List<SuggestedTarget>>()
        var displayedKeys: List<String> = emptyList()
        var labelBefore = ""
        var labelAfter = ""
        onEdt {
            val section = SuggestedTargetsSection(list, { calls += it }, formatter)
            section.refreshNow()
            val model = section.table.model as SuggestedTargetsTableModel
            displayedKeys = (0 until model.rowCount).mapNotNull { model.entryAt(it)?.key }
            list.addAll(listOf(late))
            labelBefore = section.queueAllButton.text

            section.queueAllButton.doClick()

            section.refreshNow()
            labelAfter = section.queueAllButton.text
            section.queueAllButton.doClick()
        }

        val lateKey = SuggestedTargetList.keyOf("https://late.example/x", late)
        assertEquals("Queue 3 suggested targets", labelBefore)
        assertEquals(2, calls.size)
        assertEquals(displayedKeys, calls[0].map { it.key }, "queue-all hands over the displayed rows in model order")
        assertFalse(lateKey in calls[0].map { it.key }, "an entry the table does not show is not queued")
        assertEquals(4, list.count(), "the section itself removes nothing")
        assertEquals("Queue 4 suggested targets", labelAfter)
        assertEquals(list.snapshot().map { it.key }, calls[1].map { it.key }, "after a refresh all four are shown and handed over")
    }

    @Test
    fun queueSelectedResolvesSortedViewRowsByKey() {
        val list = threeTargets()
        val calls = mutableListOf<List<SuggestedTarget>>()
        var expected: List<String> = emptyList()
        onEdt {
            val section = SuggestedTargetsSection(list, { calls += it }, formatter)
            section.refreshNow()
            val table = section.table
            table.rowSorter.sortKeys = listOf(RowSorter.SortKey(3, SortOrder.DESCENDING))
            table.setRowSelectionInterval(0, 0)
            table.addRowSelectionInterval(2, 2)
            expected = listOf(table.getValueAt(0, 3), table.getValueAt(2, 3)).map { it.toString() }

            section.queueSelectedButton.doClick()
        }

        assertEquals(listOf(URL_ACCOUNT, URL_ITEMS), expected, "URL descending puts b.example first and /items last")
        assertEquals(1, calls.size)
        assertEquals(expected, calls.single().map { it.url })
        val byUrl = list.snapshot().associateBy { it.url }
        assertEquals(expected.map { byUrl.getValue(it).key }, calls.single().map { it.key })
    }

    @Test
    fun anEmptySelectionIsPassedThroughToTheFlow() {
        val calls = mutableListOf<List<SuggestedTarget>>()
        onEdt {
            val section = SuggestedTargetsSection(threeTargets(), { calls += it }, formatter)
            section.refreshNow()
            section.queueSelectedButton.doClick()
        }

        assertEquals(listOf(emptyList<SuggestedTarget>()), calls, "the flow shows the No selection message")
    }

    @Test
    fun clearSuggestionsEmptiesTheListAndTheTable() {
        val list = threeTargets()
        onEdt {
            val section = SuggestedTargetsSection(list, {}, formatter)
            section.refreshNow()

            section.clearButton.doClick()

            assertEquals(0, list.count())
            assertEquals(0, section.table.rowCount)
            assertEquals("Suggested: 0", section.statusLabel.text)
            assertFalse(section.clearButton.isEnabled)
        }
    }

    // --- refresh -----------------------------------------------------------------------------------

    @Test
    fun selectionSurvivesARefreshByKey() {
        val list = threeTargets()
        onEdt {
            val section = SuggestedTargetsSection(list, {}, formatter)
            section.refreshNow()
            val table = section.table
            table.rowSorter.sortKeys = listOf(RowSorter.SortKey(3, SortOrder.ASCENDING))
            table.setRowSelectionInterval(1, 1)
            val selectedKey = section.selectedKeyAt(table, 1)

            list.addAll(listOf(target("https://a.example/aaa?z=1", "z", InjectionType.URL_PARAM, "1")))
            assertTrue(section.refreshIfChanged())

            assertEquals(4, table.rowCount)
            assertEquals(1, table.selectedRowCount)
            assertEquals(selectedKey, section.selectedKeyAt(table, table.selectedRow))
        }
    }

    // --- counter -----------------------------------------------------------------------------------

    @Test
    fun counterTextIsTheOnePhaseWording() {
        assertEquals("Suggested: 3", suggestedCounterText(3, false))
        assertEquals("Suggested: 500 (cap reached)", suggestedCounterText(500, true))
    }

    @Test
    fun statusLabelShowsTheCounterAndTheCap() {
        onEdt {
            val section = SuggestedTargetsSection(threeTargets(), {}, formatter)
            section.refreshNow()
            assertEquals("Suggested: 3", section.statusLabel.text)

            val capped = SuggestedTargetList(cap = 2).also { it.addAll(threeTargetsList()) }
            val cappedSection = SuggestedTargetsSection(capped, {}, formatter)
            cappedSection.refreshNow()
            assertEquals("Suggested: 2 (cap reached)", cappedSection.statusLabel.text)
        }
    }

    // --- wiring (source checks) --------------------------------------------------------------------

    @Test
    fun theQueueDialogHostsTheSectionAndRunsTheSharedFlow() {
        val panel = SourceRoots.packageFile("ui/panels/ActiveScanQueuePanel.kt").readText(Charsets.UTF_8)

        assertTrue(panel.contains("SuggestedTargetsSection("), "the dialog builds the section")
        assertTrue(panel.contains("SuggestedQueueAction("), "the section's buttons run the confirmed flow")
        assertTrue(panel.contains("SwingSuggestedQueuePrompts("), "with the Swing prompts")
        assertTrue(panel.contains("JSplitPane.VERTICAL_SPLIT"), "both tables share a vertical split")
        assertTrue(panel.contains("refreshIfChanged()"), "the timer refreshes the section on a version change")
        assertTrue(panel.contains("PlainTextTableCellRenderer"), "the queued table renders plain text too")
        val timer = panel.substring(panel.indexOf("private val refreshTimer ="), panel.indexOf("init {"))
        assertTrue(timer.contains("refreshIfChanged()"), "timer tick: $timer")
    }

    @Test
    fun viewQueuePassesThePassiveScannersSuggestedList() {
        val tabs = SourceRoots.packageFile("ui/SettingsPanelScannerTabs.kt").readText(Charsets.UTF_8)
        val call = tabs.lines().single { it.contains("ActiveScanQueuePanel.showDialog(") }

        assertTrue(call.contains("passiveAiScanner.suggestedTargets"), call)
    }

    @Test
    fun theSectionNeverReadsAnOriginalValueAndLogsNothing() {
        val section = SourceRoots.packageFile("ui/panels/SuggestedTargetsSection.kt").readText(Charsets.UTF_8)

        assertFalse(section.contains("originalValue"), "D-03: no value column")
        assertFalse(section.contains("logging()"), "D-02: no Output line")
        assertFalse(section.contains("Timer("), "the dialog's timer drives refreshes")
        assertTrue(section.contains("\"html.disable\""))
    }

    // --- helpers -----------------------------------------------------------------------------------

    private fun SuggestedTargetsSection.selectedKeyAt(
        table: javax.swing.JTable,
        viewRow: Int,
    ): String? = (table.model as SuggestedTargetsTableModel).entryAt(table.convertRowIndexToModel(viewRow))?.key

    private fun cellsOf(
        section: SuggestedTargetsSection,
        modelRow: Int,
    ): List<String> = (1..4).map { col -> cellText(section, modelRow, col) }

    private fun cellText(
        section: SuggestedTargetsSection,
        modelRow: Int,
        column: Int,
    ): String {
        val model = section.table.model
        return model.getValueAt(modelRow, column).toString()
    }

    private fun threeTargets(): SuggestedTargetList = SuggestedTargetList(clock = { 1_000L }).also { it.addAll(threeTargetsList()) }

    private fun threeTargetsList(): List<ActiveScanTarget> =
        listOf(
            target(URL_ITEMS, "id", InjectionType.URL_PARAM, "1", VulnClass.SQLI, 90),
            target(URL_SEARCH, "q", InjectionType.URL_PARAM, "x", VulnClass.XSS_REFLECTED, 70),
            target(URL_ACCOUNT, "session", InjectionType.COOKIE, COOKIE_VALUE, VulnClass.IDOR, 60),
        )

    private fun target(
        url: String,
        name: String,
        type: InjectionType,
        value: String,
        vulnClass: VulnClass = VulnClass.SQLI,
        confidence: Int = 50,
    ): ActiveScanTarget {
        val request = mock<HttpRequest>()
        whenever(request.url()).thenReturn(url)
        val rr = mock<HttpRequestResponse>()
        whenever(rr.request()).thenReturn(request)
        return ActiveScanTarget(
            originalRequest = rr,
            injectionPoint = InjectionPoint(type, name, value),
            vulnHint = VulnHint(vulnClass, confidence, "suggested"),
        )
    }

    private fun onEdt(block: () -> Unit) {
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                block()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it }
    }

    private companion object {
        const val URL_ITEMS = "https://a.example/items?id=1"
        const val URL_SEARCH = "https://a.example/search?q=x"
        const val URL_ACCOUNT = "https://b.example/account"
        const val COOKIE_VALUE = "secret-cookie-value"
    }
}
