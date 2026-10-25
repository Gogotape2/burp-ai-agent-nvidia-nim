package com.six2dez.burp.aiagent.mcp.tools

internal object McpToolErrors {
    fun isFailureOutput(output: String): Boolean = listOf("Error:", "Refused:", "Invalid ").any { output.startsWith(it) }

    fun outcome(failed: Boolean): String = if (failed) "error" else "success"

    fun serializationMessage(error: kotlinx.serialization.SerializationException): String {
        val message = error.message.orEmpty()
        val field = Regex("Field '([^']+)' is required").find(message)
        return if (field != null) "Missing required parameter: ${field.groupValues[1]}" else "Invalid tool arguments: $message"
    }
}
