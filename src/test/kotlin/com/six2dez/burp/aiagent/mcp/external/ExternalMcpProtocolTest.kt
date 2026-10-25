package com.six2dez.burp.aiagent.mcp.external

import io.modelcontextprotocol.kotlin.sdk.TextContent
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import javax.tools.ToolProvider

class ExternalMcpProtocolTest {
    @TempDir
    lateinit var temp: Path

    @Test
    fun realStdioHandshakePaginationSchemasErrorPropagationAndShutdown() =
        runBlocking {
            val source = temp.resolve("Nim17McpFixture.java")
            javaClass.getResourceAsStream("/mcp/Nim17McpFixture.java")!!.use { Files.copy(it, source) }
            assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, source.toString()))
            val executable = Path.of(System.getProperty("java.home"), "bin", if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java")
            val manager = ExternalMcpClientManager()
            try {
                val config = ExternalMcpServerConfig("fixture", ExternalMcpTransport.STDIO, command = listOf(executable.toString(), "-cp", temp.toString(), "Nim17McpFixture"))
                manager.start(listOf(config, config))
                val deadline =
                    System.nanoTime() +
                        java.util.concurrent.TimeUnit.SECONDS
                            .toNanos(15)
                while (manager.availableTools().size != 2 && System.nanoTime() < deadline) kotlinx.coroutines.delay(20)
                val tools = manager.availableTools()
                assertEquals(listOf("ext:fixture:echo", "ext:fixture:fail"), tools.map { it.name }, manager.connectionState("fixture").toString())
                assertEquals(listOf("payload"), tools.first().inputSchema.required)
                val success = manager.callToolResult("fixture", "echo", mapOf("payload" to mapOf("items" to listOf(1, true, null))))
                assertFalse(success.isError == true)
                assertTrue((success.content.single() as TextContent).text!!.contains("fixture success"))
                assertTrue(manager.callToolResult("fixture", "fail", emptyMap()).isError == true)
                assertTrue(manager.callToolResult("fixture", "missing", emptyMap()).isError == true)
            } finally {
                manager.stop()
            }
            assertTrue(manager.availableTools().isEmpty())
            assertEquals(ExternalMcpConnectionState.Disconnected, manager.connectionState("fixture"))
            manager.stop()
        }
}
