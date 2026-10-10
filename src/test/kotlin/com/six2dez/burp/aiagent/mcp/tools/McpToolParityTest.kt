package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import com.six2dez.burp.aiagent.mcp.McpRequestLimiter
import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolContext
import com.six2dez.burp.aiagent.mcp.ToolCallOrigin
import com.six2dez.burp.aiagent.redact.PrivacyMode
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Phase 29 / D-13 — the catalog and the dispatch are the same registry, so every catalog entry must
 * resolve to exactly one handler carrying that very descriptor, and every handler must publish an
 * input schema. Before the registry this compared the catalog against a separate registration list.
 */
class McpToolParityTest {
    @Test
    fun everyCatalogDescriptorHasExactlyOneHandler() {
        val descriptors = McpToolCatalog.all()
        val ids = descriptors.map { it.id }
        assertEquals(ids.size, ids.toSet().size, "the catalog lists a tool id twice: $ids")
        descriptors.forEach { descriptor ->
            val handler = McpToolCatalog.registry.handler(descriptor.id)
            assertNotNull(handler, "no handler is registered for ${descriptor.id}")
            assertEquals(descriptor, handler!!.descriptor, "the handler for ${descriptor.id} carries a different descriptor")
        }
    }

    @Test
    fun everyHandlerPublishesAnInputSchemaUnlessItIsDeclaredNoArg() {
        McpToolCatalog.all().forEach { descriptor ->
            val handler = McpToolCatalog.registry.handler(descriptor.id)
            assertNotNull(handler, "no handler is registered for ${descriptor.id}")
            val schema = handler!!.inputSchema(null)
            if (descriptor.id !in NO_ARG_TOOLS) {
                assertTrue(schema.properties.isNotEmpty(), "Missing schema mapping for ${descriptor.id}")
            }
        }
    }

    @Test
    fun executeTool_and_executeToolResult_stayAlignedForUnknownTool() {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL)
        val context =
            McpToolContext(
                api = api,
                privacyMode = PrivacyMode.OFF,
                determinismMode = false,
                hostSalt = "test",
                toolToggles = McpToolCatalog.all().associate { it.id to true },
                unsafeEnabled = false,
                unsafeTools = McpToolCatalog.unsafeToolIds(),
                enabledUnsafeTools = emptySet(),
                limiter = McpRequestLimiter(4),
                edition = BurpSuiteEdition.PROFESSIONAL,
                maxBodyBytes = 1024,
            )

        // ToolCallOrigin.UserSlashCommand: this test exercises the EXECUTOR's unknown-tool parity, not
        // the SEC-06 gate. The origin is a declaration the type system requires (plan 22-07), not a
        // behaviour switch — neither assertion below depends on which variant is passed.
        val text = McpToolExecutor.executeTool("missing_tool", null, context, ToolCallOrigin.UserSlashCommand)
        val result = McpToolExecutor.executeToolResult("missing_tool", null, context)

        assertEquals("Unknown tool: missing_tool", text)
        assertTrue(result.isError == true)
    }

    private companion object {
        val NO_ARG_TOOLS =
            setOf(
                "status",
                "editor_get",
                "project_options_get",
                "user_options_get",
                "ai_backends_list",
            )
    }
}
