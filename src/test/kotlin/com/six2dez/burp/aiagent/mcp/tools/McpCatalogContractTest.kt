package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.context.ChatContextStore
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.redact.PrivacyMode
import io.modelcontextprotocol.kotlin.sdk.TextContent
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.verifyNoInteractions

class McpCatalogContractTest {
    private fun context(
        api: MontoyaApi,
        enabled: Boolean,
        unsafe: Boolean = true,
        edition: BurpSuiteEdition = BurpSuiteEdition.PROFESSIONAL,
    ) = McpToolContext(
        api,
        PrivacyMode.OFF,
        false,
        "fixture",
        McpToolCatalog.all().associate { it.id to enabled },
        unsafe,
        McpToolCatalog.unsafeToolIds(),
        emptySet(),
        McpRequestLimiter(2),
        edition,
        32768,
        chatContextStore = ChatContextStore(),
    )

    @TestFactory
    fun everyCatalogToolRespectsDisableBeforeAccessingBurp() =
        McpToolCatalog.all().map { descriptor ->
            DynamicTest.dynamicTest(descriptor.id) {
                val api = mock<MontoyaApi>()
                val result = McpToolExecutor.executeToolResult(descriptor.id, "{malformed", context(api, false))
                assertTrue(result.isError == true)
                assertTrue((result.content.single() as TextContent).text!!.startsWith("Tool disabled:"))
                verifyNoInteractions(api)
            }
        }

    @TestFactory
    fun unsafeCatalogToolsRequireTheirPermission() =
        McpToolCatalog.all().filter { it.unsafeOnly }.map { descriptor ->
            DynamicTest.dynamicTest(descriptor.id) {
                val api = mock<MontoyaApi>()
                val result = McpToolExecutor.executeToolResult(descriptor.id, "{}", context(api, true, false))
                assertTrue(result.isError == true)
                assertTrue((result.content.single() as TextContent).text!!.startsWith("Unsafe mode is disabled"))
                verifyNoInteractions(api)
            }
        }

    @TestFactory
    fun proCatalogToolsNeverCallCommunityApis() =
        McpToolCatalog.all().filter { it.proOnly }.map { descriptor ->
            DynamicTest.dynamicTest(descriptor.id) {
                val api = mock<MontoyaApi>()
                val result = McpToolExecutor.executeToolResult(descriptor.id, "{}", context(api, true, edition = BurpSuiteEdition.COMMUNITY_EDITION))
                assertTrue(result.isError == true)
                assertTrue((result.content.single() as TextContent).text!!.contains("Professional"))
                verifyNoInteractions(api)
            }
        }

    @TestFactory
    fun malformedInputIsAnErrorForEveryParameterizedTool() =
        McpToolCatalog.all().filter { McpToolExecutor.inputSchema(it.id).properties.isNotEmpty() }.map { descriptor ->
            DynamicTest.dynamicTest(descriptor.id) {
                val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
                assertTrue(McpToolExecutor.executeToolResult(descriptor.id, "{malformed", context(api, true)).isError == true)
            }
        }
}
