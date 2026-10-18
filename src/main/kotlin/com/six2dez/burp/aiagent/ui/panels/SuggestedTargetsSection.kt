package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.scanner.SuggestedTarget
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.time.Instant
import java.time.format.DateTimeFormatter
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

private const val ROW_HEIGHT = 24
private const val COLUMN_SUGGESTED_AT = 0
private const val COLUMN_VULNERABILITY = 1
private const val COLUMN_INJECTION_POINT = 2
private const val COLUMN_URL = 3
private const val COLUMN_CONFIDENCE = 4

/** Phase 32 / D-01 — the "Queue N suggested targets" button text. */
internal fun queueAllLabel(count: Int): String = if (count == 1) "Queue 1 suggested target" else "Queue $count suggested targets"

/**
 * Phase 32 / D-02, D-07 — the one wording of the suggested-targets counter: "Suggested: N", plus
 * " (cap reached)" once the list evicted an entry for its cap. Both the Suggested section's status label
 * and the active scanner status line use it, so they can never word the counter differently.
 */
internal fun suggestedCounterText(
    count: Int,
    capReached: Boolean,
): String = if (capReached) "Suggested: $count (cap reached)" else "Suggested: $count"

/**
 * Phase 32 / D-01, D-03, D-05, D-08 — the Suggested section of the "AI Active Scanner Queue" dialog: the
 * targets passive findings suggested, in a table shaped like the queue's (Confidence instead of Status),
 * with "Queue N suggested targets", "Queue selected" and "Clear suggestions".
 *
 * The section queues nothing itself: both queue buttons hand entries to [onQueue], which runs the
 * confirmed flow (refusal check, enable prompt, active scan confirmation).
 *
 * "Queue N suggested targets" hands over the rows the table shows: N on the label is their count, and
 * the confirmation counts the same set (D-05, 32-REVIEW WR-02). An entry added since the last refresh
 * is queued only after the table shows it. An entry that left the list since the refresh (cleared, or
 * auto-queued by the full build) is harmless: the active scanner deduplicates, and only what it really
 * queued leaves the list (D-08).
 *
 * The section sends nothing, logs nothing and owns no timer; the dialog calls [refreshIfChanged] on its
 * own tick. Target-derived text is shown through [PlainTextTableCellRenderer] (research Pitfall 7) and an
 * injection point's original value is never shown (a cookie point's value is a session secret). EDT only.
 */
internal class SuggestedTargetsSection(
    private val list: SuggestedTargetList,
    private val onQueue: (List<SuggestedTarget>) -> Unit,
    formatter: DateTimeFormatter,
) : JPanel(BorderLayout(DesignTokens.Spacing.sm, DesignTokens.Spacing.sm)) {
    private val model = SuggestedTargetsTableModel(formatter)
    internal val table = JTable(model)
    internal val queueAllButton = JButton(queueAllLabel(0))
    internal val queueSelectedButton = JButton("Queue selected")
    internal val clearButton = JButton("Clear suggestions")
    internal val statusLabel = JLabel(suggestedCounterText(0, false))

    // The list version the rows were last loaded from; null until the first load.
    private var loadedVersion: Long? = null

    init {
        background = DesignTokens.Colors.surface
        add(buildHeader(), BorderLayout.NORTH)
        configureTable()
        add(JScrollPane(table), BorderLayout.CENTER)
        add(buildFooter(), BorderLayout.SOUTH)

        queueAllButton.addActionListener { onQueue(model.entries()) }
        queueSelectedButton.addActionListener { onQueue(selectedEntries()) }
        clearButton.addActionListener {
            list.clear()
            refreshNow()
        }
        queueAllButton.isEnabled = false
        clearButton.isEnabled = false
    }

    /** Reloads the rows only when the list changed since the last load (Pitfall 8); true when it did. */
    fun refreshIfChanged(): Boolean {
        if (loadedVersion == list.version()) return false
        refreshNow()
        return true
    }

    /** Reloads the rows, keeps the selected entries selected by key, and updates the labels and buttons. */
    fun refreshNow() {
        // Read before the snapshot: an add racing this refresh bumps the version past it and reloads next tick.
        val version = list.version()
        val selectedKeys = selectedEntries().mapTo(HashSet()) { it.key }
        val entries = list.snapshot()
        model.setEntries(entries)
        reselect(selectedKeys)
        loadedVersion = version

        val count = entries.size
        queueAllButton.text = queueAllLabel(count)
        queueAllButton.isEnabled = count > 0
        clearButton.isEnabled = count > 0
        statusLabel.text = suggestedCounterText(count, list.capReached())
    }

    private fun selectedEntries(): List<SuggestedTarget> =
        table.selectedRows
            .map { table.convertRowIndexToModel(it) }
            .distinct()
            .mapNotNull { model.entryAt(it) }

    private fun reselect(keys: Set<String>) {
        if (keys.isEmpty()) return
        for (modelRow in 0 until model.rowCount) {
            val viewRow = if (model.entryAt(modelRow)?.key in keys) table.convertRowIndexToView(modelRow) else -1
            if (viewRow >= 0) table.addRowSelectionInterval(viewRow, viewRow)
        }
    }

    private fun buildHeader(): JPanel {
        val header = JPanel()
        header.layout = BoxLayout(header, BoxLayout.Y_AXIS)
        header.background = DesignTokens.Colors.surface

        val title = JLabel("Suggested targets")
        title.font = DesignTokens.Typography.label
        title.foreground = DesignTokens.Colors.onSurface

        val info = JLabel("Suggested by passive findings. Nothing is sent to a target until you queue it and confirm.")
        info.font = DesignTokens.Typography.body
        info.foreground = DesignTokens.Colors.onSurfaceVariant

        header.add(title)
        header.add(info)
        return header
    }

    private fun configureTable() {
        table.font = DesignTokens.Typography.body
        table.rowHeight = ROW_HEIGHT
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.autoCreateRowSorter = true
        table.fillsViewportHeight = true
        table.background = DesignTokens.Colors.surface
        table.foreground = DesignTokens.Colors.onSurface
        table.gridColor = DesignTokens.Colors.borderSubtle
        table.tableHeader.font = DesignTokens.Typography.label
        table.tableHeader.background = DesignTokens.Colors.surface
        table.tableHeader.foreground = DesignTokens.Colors.onSurface
        PlainTextTableCellRenderer.installOn(table)
    }

    private fun buildFooter(): JPanel {
        val footer = JPanel(BorderLayout(DesignTokens.Spacing.sm, DesignTokens.Spacing.sm))
        footer.background = DesignTokens.Colors.surface

        statusLabel.font = DesignTokens.Typography.body
        statusLabel.foreground = DesignTokens.Colors.onSurfaceVariant

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, DesignTokens.Spacing.sm, 0))
        buttons.background = DesignTokens.Colors.surface
        listOf(queueAllButton, queueSelectedButton, clearButton).forEach { button ->
            styleButton(button)
            buttons.add(button)
        }

        footer.add(statusLabel, BorderLayout.WEST)
        footer.add(buttons, BorderLayout.EAST)
        return footer
    }

    // The queue dialog's outlined button look.
    private fun styleButton(button: JButton) {
        button.font = DesignTokens.Typography.label
        button.background = DesignTokens.Colors.surface
        button.foreground = DesignTokens.Colors.primary
        button.isFocusPainted = false
        button.border = BorderFactory.createLineBorder(DesignTokens.Colors.border, 1, true)
    }
}

/**
 * Phase 32 / D-03 — the Suggested table's rows: Suggested At, Vulnerability, Injection Point (TYPE:name),
 * URL and Confidence. There is deliberately no value column: an injection point's original value can be
 * a session cookie.
 */
internal class SuggestedTargetsTableModel(
    private val formatter: DateTimeFormatter,
) : AbstractTableModel() {
    private val columns = arrayOf("Suggested At", "Vulnerability", "Injection Point", "URL", "Confidence")
    private var rows: List<SuggestedTarget> = emptyList()

    fun setEntries(entries: List<SuggestedTarget>) {
        rows = entries
        fireTableDataChanged()
    }

    fun entryAt(modelRow: Int): SuggestedTarget? = rows.getOrNull(modelRow)

    /** The rows the table shows, in model order. */
    fun entries(): List<SuggestedTarget> = rows

    override fun getRowCount(): Int = rows.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String = columns[column]

    override fun getValueAt(
        rowIndex: Int,
        columnIndex: Int,
    ): Any {
        val entry = rows[rowIndex]
        val target = entry.target
        return when (columnIndex) {
            COLUMN_SUGGESTED_AT -> formatter.format(Instant.ofEpochMilli(entry.suggestedAtEpochMs))
            COLUMN_VULNERABILITY -> target.vulnHint.vulnClass.name
            COLUMN_INJECTION_POINT -> "${target.injectionPoint.type.name}:${target.injectionPoint.name}"
            COLUMN_URL -> entry.url
            COLUMN_CONFIDENCE -> "${target.vulnHint.confidence}%"
            else -> ""
        }
    }
}

/**
 * Phase 32 / research Pitfall 7 — a table cell renderer that never renders HTML. A URL or parameter
 * name starting with `<html>` comes from target traffic; Swing would otherwise render it as HTML, which
 * can load a remote image. Used by the Suggested table and by the queued table.
 */
internal class PlainTextTableCellRenderer : DefaultTableCellRenderer() {
    init {
        putClientProperty("html.disable", true)
    }

    companion object {
        /** Makes [table] render every Object and String cell through a fresh plain-text renderer. */
        fun installOn(table: JTable) {
            val renderer = PlainTextTableCellRenderer()
            table.setDefaultRenderer(Any::class.java, renderer)
            table.setDefaultRenderer(String::class.java, renderer)
        }
    }
}
