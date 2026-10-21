package com.six2dez.burp.aiagent.ui

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.awt.Container
import javax.swing.JCheckBox
import javax.swing.SwingUtilities

class WebResearchControlsTest {
    @Test
    fun masterSwitchAndIndividualToolTogglesStaySynchronized() {
        SwingUtilities.invokeAndWait {
            val search = JCheckBox()
            val fetch = JCheckBox()
            val panel = WebResearchControls.build(mapOf("web_search" to search, "web_fetch" to fetch))
            val master = find(panel)
            assertFalse(master.isSelected)
            master.doClick()
            assertTrue(search.isSelected && fetch.isSelected)
            fetch.isSelected = false
            assertFalse(master.isSelected)
            fetch.isSelected = true
            assertTrue(master.isSelected)
            master.doClick()
            assertFalse(search.isSelected || fetch.isSelected)
        }
    }

    @Test
    fun researchInstructionsDistinguishCurrentFactsFromTargetEvidence() {
        for (native in listOf(true, false)) {
            val text = ChatToolInstructions.header(native)
            assertTrue(text.contains("current external facts"))
            assertTrue(text.contains("Do not browse for routine summaries"))
            assertTrue(text.contains("does not prove the target is vulnerable"))
            assertTrue(text.contains("UNTRUSTED-WEB-DATA"))
        }
    }

    @Test
    fun controlsFitASettingsCardAndExistingTogglePersistence() {
        val selected = mapOf("web_search" to true, "web_fetch" to true)
        assertTrue(
            com.six2dez.burp.aiagent.config.McpSettings
                .parseToolToggles(
                    com.six2dez.burp.aiagent.config.McpSettings
                        .serializeToolToggles(selected),
                ) == selected,
        )
        SwingUtilities.invokeAndWait {
            val panel = WebResearchControls.build(mapOf("web_search" to JCheckBox("Search the web", true), "web_fetch" to JCheckBox("Read a page", true)))
            panel.setSize(760, 170)

            fun layout(container: Container) {
                container.doLayout()
                container.components.filterIsInstance<Container>().forEach { layout(it) }
            }
            layout(panel)
            val image = java.awt.image.BufferedImage(panel.width, panel.height, java.awt.image.BufferedImage.TYPE_INT_RGB)
            image.createGraphics().let { graphics ->
                panel.paint(graphics)
                graphics.dispose()
            }
            val path = java.io.File("build/reports/web-research-settings.png")
            path.parentFile.mkdirs()
            javax.imageio.ImageIO.write(image, "png", path)
            assertTrue(find(panel).isSelected)
        }
    }

    private fun find(container: Container): JCheckBox =
        container.components
            .flatMap {
                if (it is JCheckBox) {
                    listOf(it)
                } else if (it is Container) {
                    runCatching { listOf(find(it)) }.getOrDefault(emptyList())
                } else {
                    emptyList()
                }
            }.first()
}
