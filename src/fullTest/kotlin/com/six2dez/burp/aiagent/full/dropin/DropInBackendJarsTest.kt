package com.six2dez.burp.aiagent.full.dropin

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.spi.ExternalBackendSource
import com.six2dez.burp.aiagent.spi.Plugins
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.io.File
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

/**
 * Phase 31 / D-14 (GATE-04) — the drop-in backend JAR loader keeps working in the full build after it
 * moved out of core behind [ExternalBackendSource]. Every case runs over a `@TempDir`, never the real
 * `~/.burp-ai-agent/backends` (RESEARCH Pitfall 7).
 */
class DropInBackendJarsTest {
    @TempDir
    lateinit var tempDir: File

    private val logLines = mutableListOf<String>()
    private val errorLines = mutableListOf<String>()
    private val parent: ClassLoader = DropInBackendJarsTest::class.java.classLoader

    private fun DropInBackendJars.loadIds(): List<String> = load(parent, { logLines += it }, { errorLines += it }).map { it.id }

    @Test
    fun anEmptyDirectoryLoadsNoBackendAndOpensNoClassLoader() {
        val source = DropInBackendJars(tempDir)

        assertEquals(emptyList<String>(), source.loadIds())
        assertNull(source.openClassLoader, "no JAR, no class loader")
        assertEquals(emptyList<String>(), logLines)
        assertEquals(emptyList<String>(), errorLines)
    }

    @Test
    fun aDropInJarRegistersItsFactoryBackend() {
        writeJar(File(tempDir, "probe.jar"), DropInProbeBackendFactory::class.java.name)
        val source = DropInBackendJars(tempDir)

        val ids = source.loadIds()

        assertTrue(DropInProbeBackend.ID in ids, "the drop-in factory's backend is returned: $ids")
        assertNotNull(source.openClassLoader, "the loader stays open while its backends are registered")
        assertTrue(logLines.any { it == "Loaded external backend JARs: probe.jar" }, "logged: $logLines")
        assertEquals(emptyList<String>(), errorLines)
        source.close()
    }

    @Test
    fun closeThenLoadReRegistersTheSameBackendAndClosesThePreviousLoader() {
        writeJar(File(tempDir, "probe.jar"), DropInProbeBackendFactory::class.java.name)
        val source = DropInBackendJars(tempDir)
        val first = source.loadIds()
        val firstLoader = source.openClassLoader!!
        assertNotNull(firstLoader.getResource(MARKER), "the JAR is readable through its open loader")

        source.close()
        assertNull(source.openClassLoader, "close() forgets the loader")
        assertNull(firstLoader.getResource(MARKER), "close() closed the loader")
        val second = source.loadIds()

        assertEquals(first, second, "a second load registers the same backends")
        assertNotSame(firstLoader, source.openClassLoader, "every load opens a fresh loader")
        source.close()
    }

    @Test
    fun aMissingDirectoryIsCreatedByLoad() {
        val dir = File(tempDir, "nested/backends")
        assertFalse(dir.exists())

        assertEquals(emptyList<String>(), DropInBackendJars(dir).loadIds())

        assertTrue(dir.isDirectory, "load() creates the drop-in directory on first use")
    }

    /**
     * Phase 31 gap closure WR-06: a drop-in built against classes the extension no longer ships fails
     * with a LinkageError when its factory links. It is logged and skipped like any broken JAR.
     */
    @Test
    fun aJarWhoseFactoryFailsToFindAClassIsLoggedAndSkippedWithNoLoaderLeftOpen() {
        writeJar(File(tempDir, "stale.jar"), DropInLinkageFailureFactory::class.java.name)
        val source = DropInBackendJars(tempDir)

        assertEquals(emptyList<String>(), source.loadIds(), "a JAR that fails to link registers nothing")

        assertNull(source.openClassLoader, "the failed loader is closed, not remembered")
        val error = errorLines.single()
        assertTrue(error.startsWith("Failed loading external backend JARs: "), "logged: $errorLines")
        assertTrue(error.contains(DropInLinkageFailureFactory.MISSING_CLASS), "logged: $errorLines")
        assertTrue(logLines.none { it.startsWith("Loaded external backend JARs") }, "logged: $logLines")
    }

    @Test
    fun aJarWhoseFactoryFailsToFindAMethodIsLoggedAndSkippedWithNoLoaderLeftOpen() {
        writeJar(File(tempDir, "stale.jar"), DropInMissingMethodFactory::class.java.name)
        val source = DropInBackendJars(tempDir)

        assertEquals(emptyList<String>(), source.loadIds(), "a JAR that fails to link registers nothing")

        assertNull(source.openClassLoader, "the failed loader is closed, not remembered")
        val error = errorLines.single()
        assertTrue(error.startsWith("Failed loading external backend JARs: "), "logged: $errorLines")
        assertTrue(error.contains(DropInMissingMethodFactory.MISSING_METHOD), "logged: $errorLines")
        assertTrue(logLines.none { it.startsWith("Loaded external backend JARs") }, "logged: $logLines")
    }

    @Test
    fun aRegistryOverAJarThatFailsToLinkStillLoadsEveryBuiltInBackend() {
        writeJar(File(tempDir, "stale.jar"), DropInLinkageFailureFactory::class.java.name)
        val api = mock<MontoyaApi>()
        val logging = mock<Logging>()
        whenever(api.logging()).thenReturn(logging)

        // The internal constructor: BackendRegistry(api) would load the real home drop-in directory.
        val registry = BackendRegistry(api, listOf(DropInBackendJars(tempDir)))

        val ids = registry.listAllBackendIds()
        assertTrue(ids.containsAll(BUILT_IN_IDS), "every built-in backend is registered: $ids")
        assertFalse(DropInProbeBackend.ID in ids, "no drop-in backend is registered: $ids")
        val errors = argumentCaptor<String>()
        verify(logging, atLeastOnce()).logToError(errors.capture())
        assertEquals(
            1,
            errors.allValues.count { it.startsWith("Failed loading external backend JARs: ") },
            "one drop-in failure line: ${errors.allValues}",
        )

        registry.reload()
        registry.shutdown()
    }

    @Test
    fun aBrokenJarIsLoggedAndSkippedWithNoLoaderLeftOpen() {
        writeJar(File(tempDir, "broken.jar"), "com.example.MissingFactory")
        val source = DropInBackendJars(tempDir)

        assertEquals(emptyList<String>(), source.loadIds(), "a broken JAR registers nothing")

        assertNull(source.openClassLoader, "the failed loader is closed, not remembered")
        assertTrue(errorLines.single().startsWith("Failed loading external backend JARs: "), "logged: $errorLines")
    }

    @Test
    fun theFullClasspathRegistersExactlyTheDropInLoader() {
        val providers = Plugins.load(ExternalBackendSource::class.java)

        assertEquals(1, providers.size, "providers: $providers")
        assertTrue(providers.single() is DropInBackendJars)
    }

    private fun writeJar(
        jar: File,
        factoryClassName: String,
    ) {
        JarOutputStream(jar.outputStream()).use { out ->
            out.putNextEntry(JarEntry("META-INF/services/${AiBackendFactory::class.java.name}"))
            out.write("$factoryClassName\n".toByteArray(Charsets.UTF_8))
            out.closeEntry()
            out.putNextEntry(JarEntry(MARKER))
            out.write("marker".toByteArray(Charsets.UTF_8))
            out.closeEntry()
        }
    }

    private companion object {
        const val MARKER = "dropin-probe-marker.txt"
        val BUILT_IN_IDS =
            setOf("burp-ai", "anthropic", "lmstudio", "nvidia-nim", "ollama", "openai-compatible", "perplexity")
    }
}

/** A factory a drop-in JAR names in its services file; the class resolves through the parent loader. */
class DropInProbeBackendFactory : AiBackendFactory {
    override fun create(): AiBackend = DropInProbeBackend()
}

class DropInProbeBackend : AiBackend {
    override val id: String = ID
    override val displayName: String = "Drop-in probe"

    override fun launch(config: BackendLaunchConfig): AgentConnection = error("the probe backend is never launched")

    companion object {
        const val ID = "dropin-probe"
    }
}

/**
 * Stands in for a drop-in compiled against a class the extension removed (Phase 31 gap closure WR-06):
 * creating its backend fails to link. The missing-class name is neutral on purpose.
 */
class DropInLinkageFailureFactory : AiBackendFactory {
    override fun create(): AiBackend = throw NoClassDefFoundError(MISSING_CLASS)

    companion object {
        const val MISSING_CLASS = "com/example/RemovedHttpClient"
    }
}

/** Stands in for a drop-in calling a helper method the extension removed (Phase 31 gap closure WR-06). */
class DropInMissingMethodFactory : AiBackendFactory {
    override fun create(): AiBackend = throw NoSuchMethodError(MISSING_METHOD)

    companion object {
        const val MISSING_METHOD = "com.example.RemovedHelper.buildClient()"
    }
}
