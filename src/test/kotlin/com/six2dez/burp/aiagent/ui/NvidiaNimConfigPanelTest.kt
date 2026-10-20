package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import com.six2dez.burp.aiagent.ui.panels.BackendConfigPanel
import com.six2dez.burp.aiagent.ui.panels.BackendConfigState
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.awt.Component
import java.awt.Container
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO
import javax.swing.JButton
import javax.swing.SwingUtilities

class NvidiaNimConfigPanelTest {
    @Test
    fun defaultsButton_preservesCredentialsAndAppliesWorkingProfile() {
        SwingUtilities.invokeAndWait {
            val panel =
                BackendConfigPanel(
                    BackendConfigState(
                        nvidiaNimApiKey = "placeholder-only",
                        nvidiaNimModel = "custom/model",
                        nvidiaNimTimeoutSeconds = "60",
                    ),
                )
            panel.setBackend("nvidia-nim")
            components(panel).filterIsInstance<JButton>().first { it.text == "Use Nemotron Ultra defaults" }.doClick()
            val state = panel.currentBackendSettings()
            assertEquals("placeholder-only", state.nvidiaNimApiKey)
            assertEquals(NvidiaNimOptions.DEFAULT_MODEL, state.nvidiaNimModel)
            assertEquals("900", state.nvidiaNimTimeoutSeconds)
            assertEquals(NvidiaNimOptions(), state.nvidiaNimOptions)
            render(panel)
        }
    }

    @Test
    fun applyState_roundTripsGenerationAndRateLimits() {
        SwingUtilities.invokeAndWait {
            val panel = BackendConfigPanel()
            val options = NvidiaNimOptions(maxTokens = 24000, reasoningEffort = "high", reasoningBudget = 9000, maxConcurrency = 2, rateLimit = 10, rateWindowSeconds = 120, maxRetries = 4, historyMaxChars = 800_000)
            panel.applyState(BackendConfigState(nvidiaNimOptions = options))
            assertEquals(options, panel.currentBackendSettings().nvidiaNimOptions)
        }
    }

    private fun components(component: Component): Sequence<Component> =
        sequence {
            yield(component)
            if (component is Container) component.components.forEach { yieldAll(components(it)) }
        }

    private fun render(panel: BackendConfigPanel) {
        panel.setSize(960, 900)

        fun layout(component: Component) {
            if (component is Container) {
                component.doLayout()
                component.components.forEach { layout(it) }
            }
        }
        layout(panel)
        val image = BufferedImage(panel.width, panel.height, BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        try {
            panel.printAll(graphics)
        } finally {
            graphics.dispose()
        }
        val file = File("build/reports/nim-settings.png")
        file.parentFile.mkdirs()
        ImageIO.write(image, "png", file)
    }
}
