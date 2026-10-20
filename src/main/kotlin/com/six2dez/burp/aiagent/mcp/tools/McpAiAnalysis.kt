package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.supervisor.ToolAnalysisSession
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

internal fun executeAiAnalysis(
    input: AiAnalyzeInput,
    context: McpToolContext,
): String {
    val session =
        runCatching { initializeToolAnalysis(context) }
            .getOrElse { return "Error: ${it.message ?: "Unable to initialize AI backend"}" }
    val response = StringBuilder()
    val completed = CountDownLatch(1)
    val failure = AtomicReference<Throwable?>(null)
    return try {
        session.connection.send(
            text = input.text,
            history = emptyList(),
            onChunk = { response.append(it) },
            onComplete = {
                failure.set(it)
                completed.countDown()
            },
            jsonMode = input.jsonMode,
            maxOutputTokens = input.maxOutputTokens,
        )
        if (!completed.await(session.waitTimeoutMs, TimeUnit.MILLISECONDS)) {
            "Error: AI analysis timed out after ${TimeUnit.MILLISECONDS.toSeconds(session.waitTimeoutMs)} seconds."
        } else {
            failure.get()?.let { "Error: AI backend: ${it.message}" } ?: response.toString().trim()
        }
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        "Error: AI analysis interrupted."
    } finally {
        runCatching { session.connection.stop() }
            .onFailure { context.api.logging().logToError("[McpAiAnalysis] Connection cleanup failed: ${it.javaClass.simpleName}") }
    }
}

private fun initializeToolAnalysis(context: McpToolContext): ToolAnalysisSession {
    val supervisor = requireNotNull(context.supervisor) { "AI tool runtime is not initialized." }
    val backendId = context.aiBackendId ?: supervisor.preferredBackendId() ?: error("AI backend is not configured.")
    check(!supervisor.requiresBurpAiAndDisabled(backendId)) {
        "AI features unavailable: enable Use AI for the burp-ai backend or select an external backend."
    }
    return supervisor.openToolAnalysisSession(backendId)
}
