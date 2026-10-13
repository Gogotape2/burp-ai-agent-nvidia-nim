package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import com.six2dez.burp.aiagent.mcp.schema.toSiteMapEntry
import com.six2dez.burp.aiagent.spi.ToolHandler
import kotlinx.serialization.encodeToString
import java.util.regex.Pattern

// Phase 29 / D-13 / D-14 — the generic site-map and scope tools. Each descriptor sits next to its handler
// and was moved verbatim from the catalog; each body was moved verbatim from the executor's dispatch
// `when`. The two site-map bodies serialize raw traffic (SerializedEmissionSiteInventoryTest pins them)
// and rely on McpToolExecutor.executeToolResult's context.redactIfNeeded wrap. Contributed by
// GenericToolProvider.

private val siteMapHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "site_map",
                title = "Site map",
                description = "Displays items within the Burp site map.",
                category = "Site Map",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { GetSiteMap::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetSiteMap>(args)
        val items = api.siteMap().requestResponses()
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        // 07-03 D-03: filter site-map entries by scope when mcpScopeOnly is on.
        val scoped = McpScopeFilter.filterInScope(seq, { it.request()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSiteMapEntry()) },
        )
    }

private val siteMapRegexHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "site_map_regex",
                title = "Site map (regex)",
                description = "Displays site map items matching a regex.",
                category = "Site Map",
                defaultEnabled = true,
                secTier = SecTier.CONFIRM,
            ),
        pagedArgs = true,
        schema = { GetSiteMapRegex::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<GetSiteMapRegex>(args)
        val compiledRegex = Pattern.compile(input.regex)
        val filter =
            burp.api.montoya.sitemap.SiteMapFilter { node ->
                compiledRegex.matcher(node.url()).find()
            }
        val items = api.siteMap().requestResponses(filter)
        val seq =
            if (context.determinismMode) {
                items.sortedBy { it.request()?.url().orEmpty() }.asSequence()
            } else {
                items.asSequence()
            }
        // 07-03 D-03: scope filter applied AFTER the user-supplied SiteMapFilter.
        val scoped = McpScopeFilter.filterInScope(seq, { it.request()?.url() }, context)
        context.limitedJoin(
            scoped
                .drop(input.offset)
                .take(input.count)
                .map { toolJson.encodeToString(it.toSiteMapEntry()) },
        )
    }

private val scopeCheckHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scope_check",
                title = "Scope check",
                description = "Checks whether a URL is in scope.",
                category = "Scope",
                defaultEnabled = true,
                secTier = SecTier.AUTO,
            ),
        schema = { ScopeCheck::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ScopeCheck>(args)
        "in_scope=${api.scope().isInScope(input.url)}"
    }

private val scopeIncludeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scope_include",
                title = "Include in scope",
                description = "Includes a URL in scope.",
                category = "Scope",
                defaultEnabled = false,
                unsafeOnly = true,
                secTier = SecTier.CONFIRM_EACH,
            ),
        schema = { ScopeUpdate::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ScopeUpdate>(args)
        api.scope().includeInScope(input.url)
        "Scope include applied"
    }

private val scopeExcludeHandler: ToolHandler =
    toolHandler(
        descriptor =
            McpToolDescriptor(
                id = "scope_exclude",
                title = "Exclude from scope",
                description = "Excludes a URL from scope.",
                category = "Scope",
                defaultEnabled = false,
                unsafeOnly = true,
                // CONFIRM, not CONFIRM_EACH: excluding narrows the blast radius where scope_include widens it. The asymmetry is the point.
                secTier = SecTier.CONFIRM,
            ),
        schema = { ScopeUpdate::class.asInputSchema() },
    ) { args, context ->
        val api = context.api
        val input = decodeToolArgs<ScopeUpdate>(args)
        api.scope().excludeFromScope(input.url)
        "Scope exclude applied"
    }

/** The site-map handlers, in declared order. Declared last: top-level properties initialize in file order. */
internal val genericSiteMapHandlers: List<ToolHandler> =
    listOf(
        siteMapHandler,
        siteMapRegexHandler,
        scopeCheckHandler,
        scopeIncludeHandler,
        scopeExcludeHandler,
    )
