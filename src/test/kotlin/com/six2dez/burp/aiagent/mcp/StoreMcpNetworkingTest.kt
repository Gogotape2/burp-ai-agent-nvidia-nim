package com.six2dez.burp.aiagent.mcp

import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Phase 29 / NET-02, OQ6 (T-29-31) — the store build opens no non-Montoya client connection of its own.
 *
 * This suite runs on the store test classpath (main outputs plus the store `runtimeClasspath`), which is
 * the classpath the BApp Store JAR is assembled from. On it:
 * - no Ktor client engine can load: `ktor-client-cio` is excluded from the MCP SDK edge and the explicit
 *   Ktor client modules are `fullImplementation` only;
 * - the CIO server engine cannot load either (the store MCP server runs on Netty);
 * - the external MCP client manager is a full-build class;
 * - the MCP server classes the store does use still load, so the exclusions took nothing it needs.
 *
 * The MCP SDK's own client package is stripped from the store JAR by `bappJar` (it stays on this
 * classpath with the SDK artifact); the JAR-listing check in the plan's verification covers that half.
 */
class StoreMcpNetworkingTest {
    @Test
    fun noKtorClientEngineIsOnTheStoreClasspath() {
        assertThrows(ClassNotFoundException::class.java, { load("io.ktor.client.engine.cio.CIO") }, "ktor-client-cio must be absent")
    }

    @Test
    fun theCioServerEngineIsNotOnTheStoreClasspath() {
        assertThrows(ClassNotFoundException::class.java, { load("io.ktor.server.cio.CIO") }, "ktor-server-cio must be absent")
    }

    @Test
    fun theExternalMcpClientManagerIsNotInTheStoreBuild() {
        assertThrows(
            ClassNotFoundException::class.java,
            { load("com.six2dez.burp.aiagent.mcp.external.ExternalMcpClientManager") },
            "the external MCP client is full-build only",
        )
    }

    @Test
    fun theMcpServerClassesTheStoreUsesStillLoad() {
        STORE_SERVER_CLASSES.forEach { name ->
            assertDoesNotThrow({ load(name) }, "$name must stay on the store classpath")
        }
    }

    private fun load(name: String): Class<*> = Class.forName(name, false, StoreMcpNetworkingTest::class.java.classLoader)

    private companion object {
        val STORE_SERVER_CLASSES =
            listOf(
                "io.modelcontextprotocol.kotlin.sdk.server.Server",
                "io.modelcontextprotocol.kotlin.sdk.server.SseServerTransport",
                "io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport",
                "io.ktor.server.netty.Netty",
                "io.ktor.server.sse.SSEKt",
                "io.ktor.server.plugins.cors.routing.CORSKt",
                "com.six2dez.burp.aiagent.mcp.KtorMcpServerManager",
            )
    }
}
