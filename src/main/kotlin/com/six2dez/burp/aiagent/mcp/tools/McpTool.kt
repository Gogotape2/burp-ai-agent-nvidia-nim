package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.audit.AuditLogger
import com.six2dez.burp.aiagent.audit.Hashing
import com.six2dez.burp.aiagent.backends.http.AiAccessRefusedException
import com.six2dez.burp.aiagent.mcp.McpToolContext
import io.modelcontextprotocol.kotlin.sdk.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.TextContent

private const val MAX_ERROR_MESSAGE_LENGTH = 500
private const val MCP_TOOL_EVENT_START = "mcp_tool_start"
private const val MCP_TOOL_EVENT_END = "mcp_tool_end"
private const val MCP_TOOL_EVENT_BLOCKED = "mcp_tool_blocked"
private val unixAbsPathRegex = Regex("""/(?:Users|home|var|tmp|opt|etc|private|Library|Applications)(?:/[^\s:]+)+""")
private val windowsAbsPathRegex = Regex("""[A-Za-z]:\\(?:[^\\\s:]+\\)*[^\\\s:]*""")
private val packageClassRegex = Regex("""\b(?:[a-z_][a-z0-9_]*\.){2,}[A-Za-z_][A-Za-z0-9_$]*\b""")

interface Paginated {
    val count: Int
    val offset: Int
}

@PublishedApi
internal fun runTool(
    context: McpToolContext,
    name: String,
    argsJson: String? = null,
    execute: () -> String,
): CallToolResult {
    val normalizedArgs = argsJson?.trim().orEmpty()
    val hasArgs = normalizedArgs.isNotBlank() && normalizedArgs != "{}"
    val argsSha256 = if (hasArgs) Hashing.sha256Hex(normalizedArgs) else null
    val toolType = if (context.isUnsafeTool(name)) "unsafe" else "safe"

    val baseTelemetry =
        linkedMapOf<String, Any?>(
            "tool" to name,
            "toolType" to toolType,
            "hasArgs" to hasArgs,
        ).also { payload ->
            if (argsSha256 != null) {
                payload["argsSha256"] = argsSha256
            }
        }

    if (!context.isToolEnabled(name)) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "disabled"))
        return CallToolResult(
            content = listOf(TextContent("Tool disabled: $name")),
            isError = true,
        )
    }
    if (context.isUnsafeTool(name) && !context.isUnsafeToolAllowed(name)) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "unsafe_not_allowed"))
        return CallToolResult(
            content =
                listOf(
                    TextContent("Unsafe mode is disabled for tool: $name. Enable global unsafe mode or explicitly allow this tool."),
                ),
            isError = true,
        )
    }
    if (!context.limiter.tryAcquire()) {
        emitToolTelemetry(MCP_TOOL_EVENT_BLOCKED, baseTelemetry + mapOf("reason" to "concurrency_limited"))
        return CallToolResult(
            content = listOf(TextContent("Too many concurrent MCP requests.")),
            isError = true,
        )
    }

    emitToolTelemetry(MCP_TOOL_EVENT_START, baseTelemetry)
    val startedAtNanos = System.nanoTime()

    return try {
        val output = context.limitOutput(execute())
        val result = CallToolResult(content = listOf(TextContent(output)))
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "success",
                    "durationMs" to elapsedMs(startedAtNanos),
                    "outputChars" to output.length,
                ),
        )
        result
    } catch (e: kotlinx.serialization.SerializationException) {
        // Extract missing field from the error message for a cleaner message
        val msg = e.message.orEmpty()
        val fieldMatch = Regex("Field '([^']+)' is required").find(msg)
        val cleanMsg =
            if (fieldMatch != null) {
                "Missing required parameter: ${fieldMatch.groupValues[1]}"
            } else {
                "Invalid tool arguments: $msg"
            }
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "error",
                    "errorType" to "serialization",
                    "durationMs" to elapsedMs(startedAtNanos),
                ),
        )
        CallToolResult(
            content = listOf(TextContent(cleanMsg)),
            isError = true,
        )
    } catch (e: AiAccessRefusedException) {
        // Phase 31 / D-03: a policy outcome, not a failure. The text is the policy's own user-facing
        // refusal, so it is returned verbatim (no sanitizing, no truncation) and no stack trace is logged.
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "refused",
                    "errorType" to "ai_access_refused",
                    "durationMs" to elapsedMs(startedAtNanos),
                ),
        )
        CallToolResult(
            content = listOf(TextContent(e.message.orEmpty())),
            isError = true,
        )
    } catch (e: Exception) {
        context.api.logging().logToError(e)
        val cleanMsg = sanitizeErrorMessage(e)
        emitToolTelemetry(
            MCP_TOOL_EVENT_END,
            baseTelemetry +
                mapOf(
                    "outcome" to "error",
                    "errorType" to "exception",
                    "durationMs" to elapsedMs(startedAtNanos),
                ),
        )
        CallToolResult(
            content = listOf(TextContent(cleanMsg)),
            isError = true,
        )
    } finally {
        context.limiter.release()
    }
}

private fun elapsedMs(startedAtNanos: Long): Long = ((System.nanoTime() - startedAtNanos) / 1_000_000L).coerceAtLeast(0L)

private fun emitToolTelemetry(
    type: String,
    payload: Map<String, Any?>,
) {
    AuditLogger.emitGlobal(type, payload)
}

private fun sanitizeErrorMessage(e: Exception): String {
    var message = e.message.orEmpty().ifBlank { "Unexpected MCP tool error" }
    message = unixAbsPathRegex.replace(message, "[path]")
    message = windowsAbsPathRegex.replace(message, "[path]")
    message = packageClassRegex.replace(message, "[internal]")
    message = message.replace(Regex("\\s+"), " ").trim()
    if (message.isBlank()) {
        message = "Unexpected MCP tool error"
    }
    if (message.length > MAX_ERROR_MESSAGE_LENGTH) {
        message = message.take(MAX_ERROR_MESSAGE_LENGTH).trimEnd() + "..."
    }
    return message
}
