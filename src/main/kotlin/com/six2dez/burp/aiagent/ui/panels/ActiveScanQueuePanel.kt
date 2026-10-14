package com.six2dez.burp.aiagent.ui.panels

import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanQueueItem
import com.six2dez.burp.aiagent.scanner.SuggestedTarget
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.ui.SuggestedQueueAction
import com.six2dez.burp.aiagent.ui.SwingSuggestedQueuePrompts
import com.six2dez.burp.aiagent.ui.design.DesignTokens
import java.awt.BorderLayout
import java.awt.Dialog
import java.awt.Dimension
import java.awt.FlowLayout
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArraySet
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.Timer
import javax.swing.border.EmptyBorder
import javax.swing.table.AbstractTableModel

// Phase 32 / D-01: room for the queued table and the Suggested section, one above the other.
private const val DIALOG_MIN_HEIGHT = 560
private const val DIALOG_PREFERRED_HEIGHT = 720
private const val SPLIT_RESIZE_WEIGHT = 0.5

object ActiveScanQueuePanel {
    /**
     * Phase 32 / D-13 — a window the extension unload must close. Phase 33 owns unload in general; this
     * covers the queue dialog, whose 2-second refresh timer would otherwise outlive the extension.
     */
    internal interface UnloadClosable {
        /** Stops the window's timers and disposes it. Called on the EDT. */
        fun closeForUnload()
    }

    private val openDialogs = CopyOnWriteArraySet<UnloadClosable>()

    internal fun track(dialog: UnloadClosable) {
        openDialogs.add(dialog)
    }

    internal fun untrack(dialog: UnloadClosable) {
        openDialogs.remove(dialog)
    }

    internal fun openDialogCount(): Int = openDialogs.size

    /**
     * Phase 32 / D-13 — closes every open queue dialog and stops its refresh timer, then forgets them.
     * Unload may run off the EDT: the closes then run through [SwingUtilities.invokeLater], never
     * [SwingUtilities.invokeAndWait], so the unload thread is never blocked on the EDT.
     */
    fun disposeOpenDialogs() {
        val dialogs = openDialogs.toList()
        openDialogs.clear()
        if (dialogs.isEmpty()) return
        val closeAll = { dialogs.forEach { it.closeForUnload() } }
        if (SwingUtilities.isEventDispatchThread()) closeAll() else SwingUtilities.invokeLater(closeAll)
    }

    /**
     * Opens the "AI Active Scanner Queue" dialog: the queued targets on top and, below them, the
     * targets passive findings [suggested] (Phase 32 / D-01), which the user queues through the
     * confirmed flow.
     */
    fun showDialog(
        parent: JComponent?,
        scanner: ActiveAiScanner,
        suggested: SuggestedTargetList,
    ) {
        val dialog = QueueDialog(parent, scanner, suggested)
        track(dialog)
        dialog.isVisible = true
    }

    private class QueueDialog(
        parent: JComponent?,
        private val scanner: ActiveAiScanner,
        private val suggested: SuggestedTargetList,
    ) : JDialog(
            SwingUtilities.getWindowAncestor(parent),
            "AI Active Scanner Queue",
            Dialog.ModalityType.MODELESS,
        ),
        UnloadClosable {
        private val formatter: DateTimeFormatter =
            DateTimeFormatter
                .ofPattern("yyyy-MM-dd HH:mm:ss")
                .withZone(ZoneId.systemDefault())
        private val model = QueueTableModel(formatter)
        private val table = JTable(model)
        private val statusLabel = JLabel()
        private val refreshButton = JButton("Refresh")
        private val cancelSelectedButton = JButton("Cancel selected")
        private val clearQueueButton = JButton("Clear queue")
        private val closeButton = JButton("Close")
        private val suggestedSection = SuggestedTargetsSection(suggested, { entries -> queueSuggested(entries) }, formatter)
        private val refreshTimer =
            javax.swing.Timer(2000) {
                refreshQueue()
                suggestedSection.refreshIfChanged()
            }

        init {
            layout = BorderLayout(DesignTokens.Spacing.sm + 2, DesignTokens.Spacing.sm + 2)
            minimumSize = Dimension(900, DIALOG_MIN_HEIGHT)
            preferredSize = Dimension(1024, DIALOG_PREFERRED_HEIGHT)
            rootPane.border =
                BorderFactory.createEmptyBorder(
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.md,
                    DesignTokens.Spacing.md,
                )

            configureTable()
            val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, buildQueuePane(), suggestedSection)
            split.resizeWeight = SPLIT_RESIZE_WEIGHT
            split.border = BorderFactory.createEmptyBorder()
            add(split, BorderLayout.CENTER)
            val closeBar = JPanel(FlowLayout(FlowLayout.RIGHT, DesignTokens.Spacing.sm, 0))
            closeBar.background = DesignTokens.Colors.surface
            styleButton(closeButton, outlined = false)
            closeBar.add(closeButton)
            add(closeBar, BorderLayout.SOUTH)

            refreshButton.addActionListener {
                refreshQueue()
                suggestedSection.refreshNow()
            }
            cancelSelectedButton.addActionListener { cancelSelectedRows() }
            clearQueueButton.addActionListener { clearQueueWithConfirmation() }
            closeButton.addActionListener { dispose() }

            defaultCloseOperation = DISPOSE_ON_CLOSE
            addWindowListener(
                object : java.awt.event.WindowAdapter() {
                    override fun windowClosed(e: java.awt.event.WindowEvent?) {
                        refreshTimer.stop()
                        untrack(this@QueueDialog)
                    }
                },
            )

            refreshQueue()
            suggestedSection.refreshNow()
            refreshTimer.start()
            pack()
            setLocationRelativeTo(parent)
        }

        override fun closeForUnload() {
            refreshTimer.stop()
            dispose()
        }

        private fun configureTable() {
            table.font = DesignTokens.Typography.body
            table.rowHeight = 24
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

        // The queued table with its info label and its own buttons; the top half of the split.
        private fun buildQueuePane(): JPanel {
            val pane = JPanel(BorderLayout(DesignTokens.Spacing.sm, DesignTokens.Spacing.sm))
            pane.background = DesignTokens.Colors.surface
            val infoLabel = JLabel("Queued active scanner targets (snapshot). Select rows to cancel specific items.")
            infoLabel.font = DesignTokens.Typography.body
            infoLabel.foreground = DesignTokens.Colors.onSurfaceVariant
            pane.add(infoLabel, BorderLayout.NORTH)
            pane.add(JScrollPane(table), BorderLayout.CENTER)
            pane.add(buildFooter(), BorderLayout.SOUTH)
            return pane
        }

        private fun buildFooter(): JPanel {
            val footer = JPanel(BorderLayout(DesignTokens.Spacing.sm, DesignTokens.Spacing.sm))
            footer.background = DesignTokens.Colors.surface

            statusLabel.font = DesignTokens.Typography.body
            statusLabel.foreground = DesignTokens.Colors.onSurfaceVariant

            val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, DesignTokens.Spacing.sm, 0))
            buttons.background = DesignTokens.Colors.surface
            styleButton(refreshButton, outlined = true)
            styleButton(cancelSelectedButton, outlined = true)
            styleButton(clearQueueButton, outlined = true)
            buttons.add(refreshButton)
            buttons.add(cancelSelectedButton)
            buttons.add(clearQueueButton)

            footer.add(statusLabel, BorderLayout.WEST)
            footer.add(buttons, BorderLayout.EAST)
            return footer
        }

        private fun styleButton(
            button: JButton,
            outlined: Boolean,
        ) {
            button.font = DesignTokens.Typography.label
            button.background = DesignTokens.Colors.surface
            button.foreground = DesignTokens.Colors.primary
            button.isFocusPainted = false
            if (outlined) {
                button.border = BorderFactory.createLineBorder(DesignTokens.Colors.border, 1, true)
            } else {
                button.border =
                    EmptyBorder(DesignTokens.Spacing.sm - 2, DesignTokens.Spacing.md, DesignTokens.Spacing.sm - 2, DesignTokens.Spacing.md)
            }
        }

        private fun refreshQueue() {
            val items = scanner.getQueueItems(limit = 5_000)
            model.setItems(items)
            statusLabel.text = "Queue size: ${items.size}"
        }

        // Phase 32 / D-04, D-05: the section's queue buttons run the one confirmed flow; queued entries leave the list.
        private fun queueSuggested(entries: List<SuggestedTarget>) {
            SuggestedQueueAction(suggested, scanner, SwingSuggestedQueuePrompts(this, scanner)).queue(entries)
            refreshQueue()
            suggestedSection.refreshNow()
        }

        private fun cancelSelectedRows() {
            val selectedRows = table.selectedRows
            if (selectedRows.isEmpty()) {
                JOptionPane.showMessageDialog(
                    this,
                    "Select one or more queued rows to cancel.",
                    "No selection",
                    JOptionPane.INFORMATION_MESSAGE,
                )
                return
            }

            val ids =
                selectedRows
                    .map { table.convertRowIndexToModel(it) }
                    .distinct()
                    .mapNotNull { model.targetIdAt(it) }

            var removed = 0
            ids.forEach { id ->
                if (scanner.cancelQueuedTarget(id)) {
                    removed++
                }
            }

            refreshQueue()
            JOptionPane.showMessageDialog(
                this,
                "Cancelled $removed queued target(s).",
                "Queue updated",
                JOptionPane.INFORMATION_MESSAGE,
            )
        }

        private fun clearQueueWithConfirmation() {
            val choice =
                JOptionPane.showConfirmDialog(
                    this,
                    "Clear all queued active scan targets?",
                    "Confirm queue clear",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE,
                )
            if (choice == JOptionPane.YES_OPTION) {
                scanner.clearQueue()
                refreshQueue()
            }
        }
    }

    private class QueueTableModel(
        private val formatter: DateTimeFormatter,
    ) : AbstractTableModel() {
        private val columns = arrayOf("Queued At", "Vulnerability", "Injection Point", "URL", "Status")
        private var rows: List<ActiveScanQueueItem> = emptyList()

        fun setItems(items: List<ActiveScanQueueItem>) {
            rows = items
            fireTableDataChanged()
        }

        fun targetIdAt(modelRow: Int): String? = rows.getOrNull(modelRow)?.id

        override fun getRowCount(): Int = rows.size

        override fun getColumnCount(): Int = columns.size

        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(
            rowIndex: Int,
            columnIndex: Int,
        ): Any {
            val row = rows[rowIndex]
            return when (columnIndex) {
                0 -> formatter.format(Instant.ofEpochMilli(row.queuedAtEpochMs))
                1 -> row.vulnClass
                2 -> row.injectionPoint
                3 -> row.url
                4 -> row.status
                else -> ""
            }
        }
    }
}
