package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.mcp.tools.NativeToolProvider
import com.six2dez.burp.aiagent.mcp.tools.ToolRegistry
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.ToolProvider

/**
 * SEC-06 trust tier for a catalog tool: how much human authorisation one model-emitted invocation
 * needs. The wire string is defined once, here, and nowhere else — the approval card and any audit
 * payload both read [wireValue], so the two sinks cannot disagree.
 *
 * [AUTO] means read-only AND bounded output. A tool qualifies only if it neither mutates Burp state
 * nor pulls bulk attacker-controlled traffic into model context (D-05). That sentence is the whole
 * definition; the familiar examples (decoders, schema/catalog lookups, scope reads) illustrate it
 * but do not extend it. Consequence: `proxy_http_history`, `site_map` and `scanner_issues` are
 * read-only yet are [CONFIRM], because what they return is bulk attacker-controlled traffic.
 *
 * This tier is a SECOND, INDEPENDENT axis from [McpToolDescriptor.unsafeOnly] (D-01). `unsafeOnly`
 * is a *capability* switch — may this tool ever run at all — while `secTier` is a *trust* axis —
 * did a human authorise this particular invocation. Neither is derivable from the other:
 * `ai_analyze` and `ai_passive_scan` are [CONFIRM_EACH] without being `unsafeOnly` at all, so
 * binding the trust boundary to `unsafeOnly` would leave both of them ungated.
 */
enum class SecTier(
    val wireValue: String,
) {
    /** Runs silently, with no user decision at all (D-02). Read-only AND bounded output. */
    AUTO("auto"),

    /** Prompts, and the user may approve this tool for the rest of the session (D-02). */
    CONFIRM("confirm"),

    /** Prompts on every single call; no session memory in either direction (D-02). */
    CONFIRM_EACH("confirm_each"),
}

data class McpToolDescriptor(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val defaultEnabled: Boolean,
    val proOnly: Boolean = false,
    val unsafeOnly: Boolean = false,
    // D-03: deliberately has NO default value. A default is how a new tool silently inherits a tier
    // nobody chose; the compile error at the catalog site is the control.
    val secTier: SecTier,
)

object McpToolCatalog {
    /**
     * Phase 29 / D-13 / D-14 — every tool comes from a provider: the native tools registered here in
     * code, then every [ToolProvider] ServiceLoader finds. Built once, on first use, under the lazy
     * delegate's lock. Descriptors live with their handlers; this object is the merged view.
     */
    internal val registry: ToolRegistry by lazy { ToolRegistry(listOf(NativeToolProvider()) + Plugins.load(ToolProvider::class.java)) }

    fun all(): List<McpToolDescriptor> = registry.descriptors()

    /**
     * The tools this build offers: every tool the loaded providers supply, so it equals [all]. Since
     * BUILD-04 the flavor is decided by which providers a JAR packages (the generic provider moves to
     * `src/full` in plan 29-11), never by a filter applied here.
     */
    fun available(): List<McpToolDescriptor> = all()

    fun defaults(): Map<String, Boolean> = all().associate { it.id to it.defaultEnabled }

    fun unsafeToolIds(): Set<String> = all().filter { it.unsafeOnly }.map { it.id }.toSet()

    fun mergeWithDefaults(overrides: Map<String, Boolean>): Map<String, Boolean> {
        val merged = defaults().toMutableMap()
        overrides.forEach { (k, v) -> merged[k] = v }
        return merged
    }

    /** The ids of the core tools, compiled into every build; every other tool comes from a plug-in provider. */
    fun coreToolIds(): Set<String> = registry.coreToolIds()
}
