package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.schema.asInputSchema
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class McpSchemaContractTest {
    @Test
    fun defaultedParametersAreOptionalButRequiredUrlsRemainRequired() {
        assertTrue(
            GetProxyHttpHistory::class
                .asInputSchema()
                .required
                .orEmpty()
                .isEmpty(),
        )
        assertEquals(listOf("regex"), GetProxyHttpHistoryRegex::class.asInputSchema().required)
        assertEquals(listOf("url"), ScopeCheck::class.asInputSchema().required)
        assertEquals(listOf("url"), ScopeUpdate::class.asInputSchema().required)
        assertFalse("timeoutMs" in SendHttp1Request::class.asInputSchema().required.orEmpty())
        assertFalse("tabName" in CreateRepeaterTab::class.asInputSchema().required.orEmpty())
    }

    @Test
    fun nestedInsertionOffsetsHaveActualFieldSchemasAndRequiredNames() {
        val ranges = IntruderPrepare::class.asInputSchema().properties["insertionPoints"] as JsonObject
        val item = ranges["items"] as JsonObject
        val properties = item["properties"] as JsonObject
        assertEquals(JsonPrimitive("integer"), (properties["start"] as JsonObject)["type"])
        assertEquals(JsonPrimitive("integer"), (properties["end"] as JsonObject)["type"])
        assertEquals(setOf(JsonPrimitive("start"), JsonPrimitive("end")), (item["required"] as JsonArray).toSet())
    }

    @Test
    fun runtimeHistoryCapAndTimeoutLimitsAreAdvertised() {
        val input = McpToolExecutor.inputSchema("proxy_http_history")
        assertEquals(JsonPrimitive(1000), (input.properties["count"] as JsonObject)["maximum"])
        assertEquals(JsonPrimitive(0), (input.properties["offset"] as JsonObject)["minimum"])
        assertEquals(JsonPrimitive(600000), (McpToolExecutor.inputSchema("http1_request").properties["timeoutMs"] as JsonObject)["maximum"])
    }
}
