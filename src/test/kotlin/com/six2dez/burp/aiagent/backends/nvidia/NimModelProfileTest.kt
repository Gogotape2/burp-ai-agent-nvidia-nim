package com.six2dez.burp.aiagent.backends.nvidia

import com.six2dez.burp.aiagent.config.NvidiaNimOptions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class NimModelProfileTest {
    @Test
    fun `auto disables Ultra thinking while an explicit medium setting is retained`() {
        val automatic = mutableMapOf<String, Any?>()
        NimModelProfile.apply(automatic, NvidiaNimOptions.DEFAULT_MODEL, NvidiaNimOptions(), 16384)
        assertEquals(mapOf("reasoning_effort" to "none"), automatic)
        val explicit = mutableMapOf<String, Any?>()
        NimModelProfile.apply(explicit, NvidiaNimOptions.DEFAULT_MODEL, NvidiaNimOptions(reasoningEffort = "medium"), 16384)
        assertEquals("medium", explicit["reasoning_effort"])
    }

    @Test
    fun `GLM uses low thinking and clears earlier thinking for chat`() {
        listOf("z-ai/glm-5.3", "z-ai/glm-5.3-flash").forEach { model ->
            listOf("auto", "none", "high", "max").forEach { effort ->
                val payload = mutableMapOf<String, Any?>()
                NimModelProfile.apply(payload, model, NvidiaNimOptions(reasoningEffort = effort), 16384)
                assertEquals(if (effort in listOf("auto", "none")) "low" else effort, payload["reasoning_effort"])
                assertEquals(mapOf("clear_thinking" to true), payload["chat_template_kwargs"])
            }
        }
    }

    @Test
    fun `unsupported model-specific efforts fail before sending HTTP`() {
        assertThrows(IllegalArgumentException::class.java) {
            NimModelProfile.apply(mutableMapOf(), NvidiaNimOptions.DEFAULT_MODEL, NvidiaNimOptions(reasoningEffort = "max"), 100)
        }
        assertThrows(IllegalArgumentException::class.java) {
            NimModelProfile.apply(mutableMapOf(), "z-ai/glm-5.3", NvidiaNimOptions(reasoningEffort = "medium"), 100)
        }
    }
}
