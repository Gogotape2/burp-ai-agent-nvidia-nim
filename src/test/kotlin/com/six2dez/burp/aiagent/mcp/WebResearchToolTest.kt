package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.tools.McpToolExecutor
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.web.WebFetchInput
import com.six2dez.burp.aiagent.web.WebResearchClient
import com.six2dez.burp.aiagent.web.WebSearchInput
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Mockito
import org.mockito.kotlin.mock

class WebResearchToolTest {
    private class Client : WebResearchClient {
        val searches = mutableListOf<WebSearchInput>()
        val fetches = mutableListOf<WebFetchInput>()

        override fun search(input: WebSearchInput): String {
            searches.add(input)
            return "[UNTRUSTED-WEB-DATA] public source"
        }

        override fun fetch(input: WebFetchInput): String {
            fetches.add(input)
            return "[UNTRUSTED-WEB-DATA] public text"
        }
    }

    @Test
    fun disabledByDefaultAndBothProtocolsAdvertiseOnlyEnabledTools() {
        val client = Client()
        val disabled = context(client, false)
        assertFalse(McpToolExecutor.functionTools(disabled).any { it.name.startsWith("web_") })
        assertTrue(McpToolExecutor.executeToolResult("web_search", """{"query":"Apache CVE"}""", disabled).isError == true)
        assertTrue(client.searches.isEmpty())
        val enabled = context(client)
        assertEquals(2, McpToolExecutor.functionTools(enabled).count { it.name.startsWith("web_") })
        assertTrue(McpToolExecutor.describeTools(enabled, includeSchemas = true, includeDisabled = false).contains("web_fetch:"))
        listOf("web_search", "web_fetch").forEach {
            assertEquals(SecTier.CONFIRM, McpToolCatalog.all().single { d -> d.id == it }.secTier)
            assertFalse(McpToolCatalog.defaults()[it] ?: true)
        }
    }

    @Test
    fun enabledResearchDoesNotInheritTargetScopeOrUnsafeMode() {
        val client = Client()
        val result = McpToolExecutor.executeToolResult("web_search", """{"query":"Apache HTTP Server CVE","count":5}""", context(client).copy(scopeOnly = true))
        assertFalse(result.isError == true)
        assertEquals("Apache HTTP Server CVE", client.searches.single().query)
        val fetched = McpToolExecutor.executeToolResult("web_fetch", """{"url":"https://httpd.apache.org/security/","query":"CVE"}""", context(client))
        assertFalse(fetched.isError == true)
        assertEquals("CVE", client.fetches.single().query)
    }

    @Test
    fun protectedQueriesAndCredentialUrlsNeverLeaveTheBoundary() {
        val client = Client()
        val ctx = context(client)
        listOf("""{"query":"Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789"}""", """{"query":"Cookie: session=privatevalue"}""").forEach {
            assertTrue(McpToolExecutor.executeToolResult("web_search", it, ctx).isError == true)
        }
        assertTrue(McpToolExecutor.executeToolResult("web_fetch", """{"url":"https://example.org/?access_token=abcdefghijklmnopqrstuvwxyz0123456789"}""", ctx).isError == true)
        assertTrue(client.searches.isEmpty())
        assertTrue(client.fetches.isEmpty())
    }

    @Test
    fun structuredErrorsReturnToTheModelInsteadOfPretendingSuccess() {
        val ctx =
            context(
                object : WebResearchClient {
                    override fun search(input: WebSearchInput): String = error("Search provider returned a CAPTCHA")

                    override fun fetch(input: WebFetchInput): String = error("Web HTTP 429")
                },
            )
        val result = McpToolExecutor.executeToolResult("web_search", """{"query":"Apache CVE"}""", ctx)
        assertTrue(result.isError == true)
        assertTrue(
            result.content
                .filterIsInstance<TextContent>()
                .joinToString { it.text.orEmpty() }
                .contains("CAPTCHA"),
        )
        assertTrue(McpToolExecutor.executeToolResult("web_search", """{"query":"Apache CVE","headers":{"Authorization":"secret"}}""", ctx).isError == true)
    }

    @Test
    fun strictModePublicSourceLinksCanBeReadWithoutLeakingTargetQueries() {
        val client = Client()
        val ctx = context(client).copy(privacyMode = PrivacyMode.STRICT)
        val masked =
            "https://" +
                com.six2dez.burp.aiagent.redact.Redaction
                    .anonymizeHost("httpd.apache.org", ctx.hostSalt) + "/security/"
        val args =
            com.fasterxml.jackson.module.kotlin
                .jacksonObjectMapper()
                .writeValueAsString(mapOf("url" to masked))
        assertFalse(McpToolExecutor.executeToolResult("web_fetch", args, ctx).isError == true)
        assertEquals("https://httpd.apache.org/security/", client.fetches.single().url)
        assertTrue(McpToolExecutor.executeToolResult("web_search", """{"query":"https://private.example.test/internal"}""", ctx).isError == true)
        for (query in listOf("192.168.1.1 CVE", "2001:db8::1 CVE", "::1 CVE")) {
            val json =
                com.fasterxml.jackson.module.kotlin
                    .jacksonObjectMapper()
                    .writeValueAsString(mapOf("query" to query))
            assertTrue(McpToolExecutor.executeToolResult("web_search", json, ctx).isError == true)
        }
        assertTrue(client.searches.isEmpty())
    }

    private fun context(
        client: WebResearchClient,
        enabled: Boolean = true,
    ) = McpToolContext(
        api = mock<MontoyaApi>(defaultAnswer = Mockito.RETURNS_DEEP_STUBS),
        privacyMode = PrivacyMode.BALANCED,
        determinismMode = false,
        hostSalt = "web-tests",
        toolToggles = McpToolCatalog.defaults() + mapOf("web_search" to enabled, "web_fetch" to enabled),
        unsafeEnabled = false,
        unsafeTools = McpToolCatalog.unsafeToolIds(),
        enabledUnsafeTools = emptySet(),
        limiter = McpRequestLimiter(2),
        edition = BurpSuiteEdition.COMMUNITY_EDITION,
        maxBodyBytes = 262144,
        webResearchClient = client,
    )
}
