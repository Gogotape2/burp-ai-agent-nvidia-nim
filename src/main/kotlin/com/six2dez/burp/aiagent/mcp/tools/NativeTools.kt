@file:Suppress("ktlint:standard:filename")

package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.redact.Redaction
import com.six2dez.burp.aiagent.redact.RedactionPolicy
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.Tool
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

// Phase 29 / D-13 / D-14 — the eight extension-native tools: the tools the BApp Store build ships.
// Each descriptor sits next to its handler and was moved verbatim from McpToolCatalog's list; each body
// was moved verbatim from the executor's dispatch `when`. They are registered in code by
// McpToolCatalog, never through META-INF/services, so no classpath can remove or replace them.

/** How long `ai_analyze` waits for the backend to finish one answer. */
private const val AI_ANALYZE_TIMEOUT_SECONDS = 120L

/** Per-finding cap on the detail text `ai_findings_recent` returns. */
private const val FINDING_DETAIL_MAX_CHARS = 500

private const val AI_UNAVAILABLE_MESSAGE =
    "AI features unavailable: check that your Burp edition supports AI " +
        "and the 'Use AI' toggle is enabled. Non-AI backends remain usable via the chat panel."

private val statusHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "status",
                title = "Extension status",
                description = "Returns basic extension and Burp version status.",
                category = "Extension",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { Tool.Input() },
    ) { _, context ->
        val version = context.api.burpSuite().version()
        buildString {
            appendLine("extension=burp-ai-agent")
            appendLine("burp_version=${version.name()}")
            appendLine("burp_edition=${version.edition().name}")
        }.trim()
    }

private val issueCreateHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "issue_create",
                title = "Create audit issue",
                description = "Creates a custom audit issue in Burp's issue list for AI-discovered findings.",
                category = "Issues",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { CreateAuditIssue::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<CreateAuditIssue>(args)
        executeIssueCreate(input, context.api, context)
    }

private val aiAnalyzeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "ai_analyze",
                title = "AI Analyze",
                description = "Sends text to the active AI backend and returns the analysis result.",
                category = "AI",
                defaultEnabled = true,
                // CONFIRM_EACH while NOT unsafeOnly — D-01's independence claim made concrete: binding the trust boundary to unsafeOnly would leave this ungated.
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { AiAnalyzeInput::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<AiAnalyzeInput>(args)
        val supervisor =
            context.supervisor
                ?: return@toolHandler "AI tools not initialized."
        if (!supervisor.isAiEnabled()) {
            return@toolHandler AI_UNAVAILABLE_MESSAGE
        }
        val responseBuffer = StringBuilder()
        val completionLatch = CountDownLatch(1)
        val errorRef = AtomicReference<String?>(null)
        supervisor.send(
            text = input.text,
            history = emptyList(),
            contextJson = null,
            privacyMode = context.privacyMode,
            determinismMode = context.determinismMode,
            onChunk = { chunk -> responseBuffer.append(chunk) },
            onComplete = { err ->
                errorRef.set(err?.message)
                completionLatch.countDown()
            },
            jsonMode = input.jsonMode,
            maxOutputTokens = input.maxOutputTokens,
        )
        val completed = completionLatch.await(AI_ANALYZE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        if (!completed) return@toolHandler "AI request timed out after $AI_ANALYZE_TIMEOUT_SECONDS seconds."
        val error = errorRef.get()
        if (error != null) return@toolHandler "AI error: $error"
        responseBuffer.toString().trim()
    }

private val aiPassiveScanHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "ai_passive_scan",
                title = "AI Passive Scan",
                description = "Queues requests for AI passive security analysis and returns the count enqueued.",
                category = "AI",
                defaultEnabled = true,
                // CONFIRM_EACH while NOT unsafeOnly — D-01's independence claim made concrete: binding the trust boundary to unsafeOnly would leave this ungated.
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { AiPassiveScanInput::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<AiPassiveScanInput>(args)
        val supervisor = context.supervisor
        // B2 fix: check AI gate BEFORE passiveScanner null check
        if (supervisor == null || !supervisor.isAiEnabled()) {
            return@toolHandler AI_UNAVAILABLE_MESSAGE
        }
        val scanner =
            context.passiveScanner
                ?: return@toolHandler "Passive scanner not available."

        // From Burp 2026.9, proxy history elements implement only ProxyHttpRequestResponse,
        // which does not extend HttpRequestResponse, so each kept entry is converted
        // rather than casting the list (issue #90). Converting after take() keeps large
        // histories cheap.
        val allHistory: List<ProxyHttpRequestResponse> = context.api.proxy().history()
        val filtered =
            if (input.siteMapUrl != null) {
                allHistory.filter { entry ->
                    runCatching { entry.url().contains(input.siteMapUrl) }.getOrDefault(false)
                }
            } else {
                allHistory
            }
        val requests =
            filtered.take(input.maxRequests).map { entry ->
                HttpRequestResponse.httpRequestResponse(entry.request(), entry.response(), entry.annotations())
            }
        if (requests.isEmpty()) return@toolHandler "No matching requests found."
        val count = scanner.manualScan(requests)
        "Queued $count requests for AI passive scan."
    }

private val aiFindingsRecentHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "ai_findings_recent",
                title = "AI Recent Findings",
                description = "Returns the most recent AI passive scan findings (up to n).",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { AiFindingsRecentInput::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<AiFindingsRecentInput>(args)
        val scanner =
            context.passiveScanner
                ?: return@toolHandler "Passive scanner not available."
        val findings = scanner.getLastFindings(input.n)
        if (findings.isEmpty()) return@toolHandler "No findings recorded yet."
        findings.joinToString("\n\n") { f ->
            "[${f.timestamp}] ${f.title} (${f.severity}) - ${f.url}: ${f.detail.take(FINDING_DETAIL_MAX_CHARS)}"
        }
    }

private val redactPreviewHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "redact_preview",
                title = "Redact Preview",
                description = "Applies the extension's privacy redaction engine to arbitrary text and returns the redacted result.",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { RedactPreviewInput::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<RedactPreviewInput>(args)
        val mode = PrivacyMode.valueOf(input.mode.uppercase())
        val policy = RedactionPolicy.fromMode(mode)
        Redaction.apply(input.text, policy, stableHostSalt = context.hostSalt)
    }

private val aiAuditQueryHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "ai_audit_query",
                title = "AI Audit Query",
                description = "Returns recent AI request audit log entries (hashes only unless verbose mode is enabled).",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { AiAuditQueryInput::class.asInputSchema() },
    ) { args, context ->
        val input = decodeToolArgs<AiAuditQueryInput>(args)
        val logger =
            context.aiRequestLogger
                ?: return@toolHandler "Audit logging not configured."
        val entries = logger.entries().takeLast(input.n)
        if (entries.isEmpty()) return@toolHandler "No audit entries recorded."
        entries.joinToString("\n") { e ->
            "id:${e.id} type:${e.type} source:${e.source} backend:${e.backendId} detail:${e.detail}"
        }
    }

private val aiBackendsListHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "ai_backends_list",
                title = "AI Backends List",
                description = "Lists available AI backends and reports the current active backend and connection state.",
                category = "AI",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { Tool.Input() },
    ) { _, context ->
        val registry = context.backendRegistry
        val supervisor = context.supervisor
        if (registry == null || supervisor == null) return@toolHandler "Registry not available."
        val ids = registry.listAllBackendIds()
        val status = supervisor.status()
        buildString {
            appendLine("Available backends: ${ids.joinToString(", ")}")
            appendLine("Current backend: ${status.backendId ?: "none"}")
            append("State: ${status.state}")
        }
    }

/**
 * The core tool provider. McpToolCatalog registers it in code ahead of every ServiceLoader provider,
 * and the registry treats its ids as the core set ([ToolRegistry.coreToolIds]).
 */
class NativeToolProvider : ToolProvider {
    override fun handlers(): List<ToolHandler> =
        listOf(
            statusHandler,
            issueCreateHandler,
            aiAnalyzeHandler,
            aiPassiveScanHandler,
            aiFindingsRecentHandler,
            redactPreviewHandler,
            aiAuditQueryHandler,
            aiBackendsListHandler,
        )
}
