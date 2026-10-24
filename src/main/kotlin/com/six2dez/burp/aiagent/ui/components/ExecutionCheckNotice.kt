package com.six2dez.burp.aiagent.ui.components

import com.six2dez.burp.aiagent.ui.design.DesignTokens
import java.awt.BorderLayout
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.border.EmptyBorder

internal class ExecutionCheckNotice(
    message: String,
    canRun: Boolean,
    onRun: () -> Unit,
) : JPanel(BorderLayout(DesignTokens.Spacing.sm, DesignTokens.Spacing.xs)) {
    init {
        isOpaque = false
        border = EmptyBorder(DesignTokens.Spacing.sm, DesignTokens.Spacing.md, DesignTokens.Spacing.sm, DesignTokens.Spacing.md)
        add(
            SubtleNotice().apply {
                setMessage(SubtleNotice.Level.WARN, message)
            },
            BorderLayout.CENTER,
        )
        val run =
            JButton("Выполнить проверку").apply {
                isEnabled = canRun
                toolTipText = if (canRun) "Новый запрос с текущими инструментами, областью и правилами подтверждения." else "Инструменты HTTP/активной проверки недоступны в текущих настройках."
                addActionListener {
                    isEnabled = false
                    onRun()
                }
            }
        add(run, BorderLayout.SOUTH)
    }
}
