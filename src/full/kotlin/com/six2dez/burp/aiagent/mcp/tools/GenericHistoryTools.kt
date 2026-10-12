package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.mcp.schema.toSerializableForm
import com.six2dez.burp.aiagent.spi.ToolHandler
import kotlinx.serialization.encodeToString
import java.util.regex.Pattern

// Phase 29 / D-13 / D-14 — the generic proxy-history tools. Each descriptor sits next to its handler and
// was moved verbatim from the catalog; each body was moved verbatim from the executor's dispatch `when`.
// Four of these bodies serialize raw traffic (SerializedEmissionSiteInventoryTest pins them); none
// redacts anything itself — McpToolExecutor.executeToolResult wraps every handler result in
// context.redactIfNeeded. Contributed by GenericToolProvider.

/** Upper bound on the proxy history items one `proxy_history_annotate` call may annotate. */
private const val ANNOTATE_MAX_ITEMS = 500

private val proxyHttpHistoryHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_http_history",
                title = "Proxy HTTP history",
                description = "Displays items within the proxy HTTP history.",
                category = "History",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { context ->
            val allowUnpreprocessed = context?.allowUnpreprocessedProxyHistory ?: true
            if (allowUnpreprocessed) {
                GetProxyHttpHistory::class.asInputSchema()
            } else {
                GetProxyHttpHistoryRestricted::class.asInputSchema()
            }
        },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetProxyHttpHistory>(args)
        ensureAllowedProxyHistoryCount(input.count, context.proxyHistoryMaxItemsPerRequest)
        val includeRaw = context.allowUnpreprocessedProxyHistory && input.includeUnpreprocessedResponse
        val items = api.proxy().history()
        val preprocess =
            context.responsePreprocessorSettings().copy(
                preprocessProxyHistory = !includeRaw,
            )
        val seq =
            orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }
                .let { s ->
                    if (input.listenerPort !=
                        null
                    ) {
                        s.filter { it.listenerPort() == input.listenerPort }
                    } else {
                        s
                    }
                }
        // 07-03 D-03: filter by Burp scope when mcpScopeOnly is on.
        val scoped = McpScopeFilter.filterInScope(seq, { it.request()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSerializableForm(preprocess)) },
        )
    }

private val proxyHttpHistoryRegexHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_http_history_regex",
                title = "Proxy HTTP history (regex)",
                description = "Displays proxy HTTP history items matching a regex.",
                category = "History",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { context ->
            val allowUnpreprocessed = context?.allowUnpreprocessedProxyHistory ?: true
            if (allowUnpreprocessed) {
                GetProxyHttpHistoryRegex::class.asInputSchema()
            } else {
                GetProxyHttpHistoryRegexRestricted::class.asInputSchema()
            }
        },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetProxyHttpHistoryRegex>(args)
        ensureAllowedProxyHistoryCount(input.count, context.proxyHistoryMaxItemsPerRequest)
        val includeRaw = context.allowUnpreprocessedProxyHistory && input.includeUnpreprocessedResponse
        val compiledRegex = Pattern.compile(input.regex)
        val items = api.proxy().history { it.contains(compiledRegex) }
        val preprocess =
            context.responsePreprocessorSettings().copy(
                preprocessProxyHistory = !includeRaw,
            )
        val seq = orderedProxyHistory(items, context) { it.request()?.toString().orEmpty() }
        // 07-03 D-03: filter by Burp scope when mcpScopeOnly is on.
        val scoped = McpScopeFilter.filterInScope(seq, { it.request()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSerializableForm(preprocess)) },
        )
    }

// The loop's two `continue`s and one `break` are the verbatim body moved out of the dispatch `when`;
// restructuring it would change a security-relevant scope filter for a style rule.
@Suppress("LoopWithTooManyJumpStatements")
private val proxyHistoryAnnotateHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_history_annotate",
                title = "Annotate proxy history",
                description = "Adds notes/highlights to proxy history items matching a regex.",
                category = "History",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM,
            ),
        schema = { ProxyHistoryAnnotate::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ProxyHistoryAnnotate>(args)
        val compiledRegex = Pattern.compile(input.regex)
        val items = api.proxy().history { it.contains(compiledRegex) }
        val highlightColor = parseHighlightColor(input.highlight)
        val limitValue = input.limit.coerceAtLeast(1).coerceAtMost(ANNOTATE_MAX_ITEMS)
        // 07-03 D-03: per-call scopeOnly retained as a backwards-compatible
        // override; OR'd with the global ctx.scopeOnly so either gate filters.
        val effectiveScopeOnly = input.scopeOnly || context.scopeOnly
        val annotated = mutableListOf<String>()
        for (item in items) {
            val url = item.request()?.url() ?: continue
            if (effectiveScopeOnly && !api.scope().isInScope(url)) continue
            if (input.note.isNotBlank()) {
                item.annotations().setNotes(input.note)
            }
            if (highlightColor != null) {
                item.annotations().setHighlightColor(highlightColor)
            }
            annotated.add(maybeAnonymizeUrl(url, context))
            if (annotated.size >= limitValue) break
        }
        if (annotated.isEmpty()) {
            "No matching proxy history items"
        } else {
            buildString {
                appendLine("Annotated ${annotated.size} item(s):")
                annotated.forEach { appendLine("url=$it") }
            }.trim()
        }
    }

private val responseBodySearchHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "response_body_search",
                title = "Search response bodies",
                description = "Searches response bodies in proxy history using a regex.",
                category = "History",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { ResponseBodySearch::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ResponseBodySearch>(args)
        val compiledRegex = Pattern.compile(input.regex)
        // 07-03 D-03: per-call scopeOnly retained as override; OR'd with global.
        val effectiveScopeOnly = input.scopeOnly || context.scopeOnly
        val matches = mutableListOf<String>()
        api.proxy().history().forEach { item ->
            val url = item.request()?.url() ?: return@forEach
            if (effectiveScopeOnly && !api.scope().isInScope(url)) return@forEach
            val response = item.response()?.toString().orEmpty()
            if (response.isBlank()) return@forEach
            val body = response.substringAfter("\r\n\r\n", "")
            val boundedBody = boundForRegexScan(body)
            val matcher = compiledRegex.matcher(boundedBody)
            var count = 0
            while (matcher.find()) count++
            if (count > 0) {
                val safeUrl = maybeAnonymizeUrl(url, context)
                matches.add("url=$safeUrl matches=$count response_bytes=${body.toByteArray(Charsets.UTF_8).size}")
            }
        }
        val sorted = if (context.determinismMode) matches.sorted() else matches
        val slice = sorted.drop(input.offset.coerceAtLeast(0)).take(input.count.coerceAtLeast(1))
        if (slice.isEmpty()) "No matches found" else slice.joinToString(separator = "\n")
    }

private val proxyWsHistoryHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_ws_history",
                title = "Proxy WebSocket history",
                description = "Displays items within the proxy WebSocket history.",
                category = "History",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { GetProxyWebsocketHistory::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetProxyWebsocketHistory>(args)
        val items = api.proxy().webSocketHistory()
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        // 07-03 D-03: filter WebSocket frames by the upgrade-request URL when
        // mcpScopeOnly is on. ProxyWebSocketMessage.upgradeRequest() returns
        // a non-null HttpRequest (Montoya 2026.2) so .url() is always derivable.
        val scoped = McpScopeFilter.filterInScope(seq, { it.upgradeRequest()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSerializableForm()) },
        )
    }

private val proxyWsHistoryRegexHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "proxy_ws_history_regex",
                title = "Proxy WebSocket history (regex)",
                description = "Displays WebSocket history items matching a regex.",
                category = "History",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { GetProxyWebsocketHistoryRegex::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetProxyWebsocketHistoryRegex>(args)
        val compiledRegex = Pattern.compile(input.regex)
        val items = api.proxy().webSocketHistory { it.contains(compiledRegex) }
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.payload()?.toString().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        // 07-03 D-03: same upgrade-URL scope filter as proxy_ws_history.
        val scoped = McpScopeFilter.filterInScope(seq, { it.upgradeRequest()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSerializableForm()) },
        )
    }

/** The history handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericHistoryHandlers: List<ToolHandler> =
    listOf(
        proxyHttpHistoryHandler,
        proxyHttpHistoryRegexHandler,
        proxyHistoryAnnotateHandler,
        responseBodySearchHandler,
        proxyWsHistoryHandler,
        proxyWsHistoryRegexHandler,
    )
