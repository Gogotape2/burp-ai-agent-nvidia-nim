package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.scanner.ActiveScannerStatus
import com.six2dez.burp.aiagent.scanner.PassiveAiScannerStatus
import com.six2dez.burp.aiagent.ui.components.ScannerStatusPanel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.BorderLayout
import java.awt.Color
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import javax.swing.JCheckBox
import javax.swing.JPanel
import javax.swing.SwingUtilities

class ScannerStatusPanelTest {
    @Test
    fun statusUsesSeparatePlainRowsWhenHtmlIsDisabled() {
        SwingUtilities.invokeAndWait {
            val status = ScannerStatusPanel()
            status.passiveLabel.putClientProperty("html.disable", true)
            status.activeLabel.putClientProperty("html.disable", true)
            status.showStatus(PassiveAiScannerStatus(true, 2151, 10, 0, 0), ActiveScannerStatus(true, 0, false, 23, 0, null))
            assertEquals("Passive: 2151 done | 10 findings", status.passiveLabel.text)
            assertEquals("Active: 0 queued | 23 done", status.activeLabel.text)
            assertFalse(status.passiveLabel.text.contains('<'))
            assertFalse(status.activeLabel.text.contains('<'))
            status.setSize(460, 54)
            status.doLayout()
            assertTrue(status.activeLabel.y > status.passiveLabel.y)

            val preview =
                JPanel(BorderLayout(0, 12)).apply {
                    background = Color.WHITE
                    border = javax.swing.BorderFactory.createEmptyBorder(16, 16, 16, 16)
                    add(status, BorderLayout.CENTER)
                    add(JCheckBox("Automatically approve tool calls", false), BorderLayout.SOUTH)
                    setSize(490, 120)
                    doLayout()
                }
            val image = BufferedImage(preview.width, preview.height, BufferedImage.TYPE_INT_RGB)
            image.createGraphics().let { graphics ->
                preview.paint(graphics)
                graphics.dispose()
            }
            val file = File("build/reports/nim6-ui-preview.png")
            file.parentFile.mkdirs()
            ImageIO.write(image, "png", file)
        }
    }
}
