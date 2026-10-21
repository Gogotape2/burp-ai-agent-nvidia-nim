package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.audit.DiagnosticSanitizer
import com.six2dez.burp.aiagent.audit.ExecutionJournal
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dialog
import java.awt.Dimension
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JFileChooser
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.SwingWorker
import javax.swing.Timer
import javax.swing.table.DefaultTableModel

internal object ExecutionJournalDialog {
    private const val REFRESH_MS = 500
    private const val SPLIT_WEIGHT = 0.5
    private const val WIDTH = 1000
    private const val HEIGHT = 650

    fun show(
        parent: Component,
        journal: ExecutionJournal,
    ): JDialog {
        val dialog = JDialog(SwingUtilities.getWindowAncestor(parent), "Execution log", Dialog.ModalityType.MODELESS)
        val model =
            object : DefaultTableModel(arrayOf("Time", "Step", "Stage", "Details"), 0) {
                override fun isCellEditable(
                    row: Int,
                    column: Int,
                ): Boolean = false
            }
        val table = JTable(model)
        val details =
            JTextArea().apply {
                isEditable = false
                lineWrap = true
                wrapStyleWord = true
            }
        val status = JLabel("Arguments and results are redacted in this view. Entries and field sizes are bounded.")
        val preview = JButton("Export preview")
        val save = JButton("Save preview...").apply { isEnabled = false }
        var export: String? = null
        var rendered = emptyList<com.six2dez.burp.aiagent.audit.ExecutionEntry>()
        val summaries = mutableMapOf<com.six2dez.burp.aiagent.audit.ExecutionEntry, String>()
        val timer =
            Timer(REFRESH_MS) {
                val current = journal.snapshot()
                if (current != rendered) {
                    summaries.keys.retainAll(current.toSet())
                    rendered = current
                    model.rowCount = 0
                    current.forEach { model.addRow(arrayOf(SimpleDateFormat("HH:mm:ss").format(Date(it.timeMs)), it.step, it.stage, summaries.getOrPut(it) { DiagnosticSanitizer.sanitize(it.detail) })) }
                }
            }
        table.selectionModel.addListSelectionListener {
            rendered.getOrNull(table.selectedRow)?.let { entry ->
                details.text = "${entry.stage}: ${DiagnosticSanitizer.sanitize(entry.detail)}\n\nArguments:\n${DiagnosticSanitizer.sanitize(entry.arguments.orEmpty())}\n\nResult:\n${DiagnosticSanitizer.sanitize(entry.result.orEmpty())}"
                details.caretPosition = 0
                save.isEnabled = false
            }
        }
        preview.addActionListener { prepareExport(journal, details, status, preview, save) { export = it } }
        save.addActionListener {
            val value = export ?: return@addActionListener
            val chooser = JFileChooser().apply { selectedFile = java.io.File("burp-ai-agent-diagnostics-${System.currentTimeMillis()}.json") }
            if (chooser.showSaveDialog(dialog) != JFileChooser.APPROVE_OPTION) return@addActionListener
            save.isEnabled = false
            object : SwingWorker<Unit, Unit>() {
                override fun doInBackground() {
                    Files.writeString(chooser.selectedFile.toPath(), value, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                }

                override fun done() {
                    runCatching { get() }.onSuccess { status.text = "Export saved." }.onFailure { JOptionPane.showMessageDialog(dialog, "Could not create the export. Choose a new filename and a writable folder.") }
                    save.isEnabled = true
                }
            }.execute()
        }
        val buttons =
            JPanel().apply {
                add(preview)
                add(save)
            }
        val bottom =
            JPanel(BorderLayout()).apply {
                add(status, BorderLayout.CENTER)
                add(buttons, BorderLayout.SOUTH)
            }
        dialog.add(JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), JScrollPane(details)).apply { resizeWeight = SPLIT_WEIGHT }, BorderLayout.CENTER)
        dialog.add(bottom, BorderLayout.SOUTH)
        dialog.preferredSize = Dimension(WIDTH, HEIGHT)
        dialog.defaultCloseOperation = JDialog.DISPOSE_ON_CLOSE
        dialog.addWindowListener(
            object : java.awt.event.WindowAdapter() {
                override fun windowClosed(e: java.awt.event.WindowEvent?) {
                    timer.stop()
                }
            },
        )
        dialog.pack()
        dialog.setLocationRelativeTo(parent)
        timer.start()
        dialog.isVisible = true
        return dialog
    }

    private fun prepareExport(
        journal: ExecutionJournal,
        details: JTextArea,
        status: JLabel,
        preview: JButton,
        save: JButton,
        accepted: (String) -> Unit,
    ) {
        preview.isEnabled = false
        save.isEnabled = false
        status.text = "Preparing redacted preview..."
        object : SwingWorker<String, Unit>() {
            override fun doInBackground(): String = journal.exportPreview()

            override fun done() {
                runCatching { get() }
                    .onSuccess { value ->
                        accepted(value)
                        details.text = value
                        details.caretPosition = 0
                        save.isEnabled = true
                        status.text = "Review this redacted JSON before saving. Only this preview will be written."
                    }.onFailure { status.text = "Could not prepare the preview; no file was written." }
                preview.isEnabled = true
            }
        }.execute()
    }
}
