package com.six2dez.burp.aiagent.mcp.tools

import com.six2dez.burp.aiagent.mcp.McpToolCatalog
import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.spi.ToolHandler
import com.six2dez.burp.aiagent.spi.ToolProvider
import io.modelcontextprotocol.kotlin.sdk.Tool
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Phase 29 / D-13 / BUILD-01 — the tool registry's construction contract.
 *
 * The registry is the one place every MCP and chat tool call is looked up, and a plug-in provider is
 * loaded through ServiceLoader. A provider that could re-register `status` or `redact_preview` would
 * inherit an AUTO tier nobody assigned to it (T-29-11), so construction must FAIL on any id or alias
 * collision, naming both providers. Fake providers are injected by constructing a registry directly;
 * none is registered through `src/test/resources/META-INF/services`, which every store test would see.
 *
 * Phase 29 (D-16): the two tests that build a registry over the real `GenericToolProvider` (its alias
 * table, and core ids that exclude its tools) run in FullToolRegistryTest, on the full classpath.
 */
class ToolRegistryTest {
    @Test
    fun aDuplicateToolIdAcrossProvidersFailsConstructionNamingBothProviders() {
        val error =
            assertThrows<IllegalStateException> {
                ToolRegistry(listOf(AlphaProvider(listOf("dup_tool")), ZuluProvider(listOf("dup_tool"))))
            }
        val message = error.message.orEmpty()
        assertTrue(message.contains("dup_tool"), "the error must name the colliding id: $message")
        assertTrue(message.contains(AlphaProvider::class.java.name), "the error must name the first provider: $message")
        assertTrue(message.contains(ZuluProvider::class.java.name), "the error must name the second provider: $message")
    }

    @Test
    fun aProviderCannotShadowACoreToolId() {
        val error =
            assertThrows<IllegalStateException> {
                ToolRegistry(listOf(NativeToolProvider(), ZuluProvider(listOf("status"))))
            }
        val message = error.message.orEmpty()
        assertTrue(message.contains(NativeToolProvider::class.java.name), message)
        assertTrue(message.contains(ZuluProvider::class.java.name), message)
    }

    @Test
    fun anAliasEqualToAnExistingToolIdFailsConstruction() {
        // Upper-case on purpose: aliases are matched trimmed and lower-cased, so "A" IS "a".
        val error =
            assertThrows<IllegalStateException> {
                ToolRegistry(listOf(AlphaProvider(listOf("a")), ZuluProvider(listOf("b"), mapOf("A" to "b"))))
            }
        val message = error.message.orEmpty()
        assertTrue(message.contains(AlphaProvider::class.java.name), message)
        assertTrue(message.contains(ZuluProvider::class.java.name), message)
    }

    @Test
    fun anAliasNamingAnUnknownToolFailsConstruction() {
        val error =
            assertThrows<IllegalStateException> {
                ToolRegistry(listOf(AlphaProvider(listOf("a"), mapOf("shortcut" to "missing_tool"))))
            }
        assertTrue(error.message.orEmpty().contains("missing_tool"), error.message)
    }

    @Test
    fun theSameAliasFromTwoProvidersFailsConstruction() {
        assertThrows<IllegalStateException> {
            ToolRegistry(
                listOf(
                    AlphaProvider(listOf("a"), mapOf("shared" to "a")),
                    ZuluProvider(listOf("z"), mapOf("shared" to "z")),
                ),
            )
        }
    }

    @Test
    fun descriptorsAreCoreFirstThenProvidersByClassNameEachInDeclaredOrder() {
        // Deliberately passed out of order: Zulu before Alpha, natives last.
        fun build() = ToolRegistry(listOf(ZuluProvider(listOf("z2", "z1")), AlphaProvider(listOf("a1")), NativeToolProvider()))

        val expected = NATIVE_IDS + listOf("a1", "z2", "z1")
        val first = build().descriptors().map { it.id }
        val second = build().descriptors().map { it.id }
        assertEquals(expected, first)
        assertEquals(first, second, "the order must not depend on the construction")
    }

    @Test
    fun theCatalogRegistryIsBuiltOnceUnderConcurrentAccess() {
        // The delegate must be the synchronized lazy: that is what makes a concurrent FIRST access build
        // one registry. Checked by type because a JVM that already touched the catalog cannot re-run a
        // first access; the race below then proves every thread observes the one instance.
        val delegateField = McpToolCatalog::class.java.getDeclaredField("registry\$delegate")
        delegateField.isAccessible = true
        assertEquals("kotlin.SynchronizedLazyImpl", delegateField.get(McpToolCatalog).javaClass.name)

        val threads = 8
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        val seen = Collections.synchronizedList(mutableListOf<ToolRegistry>())
        try {
            repeat(threads) {
                pool.execute {
                    start.await()
                    seen.add(McpToolCatalog.registry)
                }
            }
            start.countDown()
        } finally {
            pool.shutdown()
            assertTrue(pool.awaitTermination(AWAIT_SECONDS, TimeUnit.SECONDS), "the racing threads did not finish")
        }
        assertEquals(threads, seen.size)
        seen.forEach { assertSame(seen.first(), it) }
    }

    private open class FakeProvider(
        private val ids: List<String>,
        private val aliasTable: Map<String, String>,
    ) : ToolProvider {
        override fun handlers(): List<ToolHandler> = ids.map(::fakeHandler)

        override fun aliases(): Map<String, String> = aliasTable
    }

    private class AlphaProvider(
        ids: List<String>,
        aliases: Map<String, String> = emptyMap(),
    ) : FakeProvider(ids, aliases)

    private class ZuluProvider(
        ids: List<String>,
        aliases: Map<String, String> = emptyMap(),
    ) : FakeProvider(ids, aliases)

    private companion object {
        const val AWAIT_SECONDS = 30L

        val NATIVE_IDS =
            listOf(
                "status",
                "issue_create",
                "ai_analyze",
                "ai_passive_scan",
                "ai_findings_recent",
                "redact_preview",
                "ai_audit_query",
                "ai_backends_list",
            )

        fun fakeHandler(id: String): ToolHandler =
            toolHandler(
                descriptor =
                    McpToolDescriptor(
                        id = id,
                        title = id,
                        description = "fake tool $id",
                        category = "Test",
                        defaultEnabled = true,
                        secTier = SecTier.CONFIRM_EACH,
                    ),
                schema = { Tool.Input() },
            ) { _, _ -> id }
    }
}
