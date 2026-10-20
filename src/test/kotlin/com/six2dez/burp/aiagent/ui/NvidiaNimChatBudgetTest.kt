package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.mockito.Mockito

class NvidiaNimChatBudgetTest {
    @Test
    fun chatSendHonorsNimTokenSettingInsteadOfTheGeneric4096Cap() {
        val settings = TestSettings.baselineSettings().copy(preferredBackendId = "nvidia-nim", nvidiaNimOptions = NvidiaNimOptions(maxTokens = 24000))
        val harness = ChatPanelTestHarness.create(modelResponse = "OK", settings = settings)
        try {
            ChatPanelTestHarness.sendUserMessage(harness, "hello")
            ChatPanelTestHarness.drainEdt()
            val call = Mockito.mockingDetails(harness.supervisor).invocations.single { it.method.name == "sendChat" }
            assertEquals("nvidia-nim", call.getArgument<String>(1))
            assertEquals(24000, call.getArgument<Int>(11))
        } finally {
            harness.panel.shutdown()
        }
    }
}
