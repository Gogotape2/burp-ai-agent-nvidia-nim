package com.six2dez.burp.aiagent.full.dropin

import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.AiBackendFactory
import com.six2dez.burp.aiagent.spi.ExternalBackendSource
import java.io.File
import java.io.IOException
import java.net.URLClassLoader
import java.util.ServiceConfigurationError
import java.util.ServiceLoader

/**
 * Phase 31 / D-14 (WR-05, ADR-18 OQ8) — the drop-in backend JAR loader, moved here from core's
 * `BackendRegistry`. Registered through `META-INF/services/com.six2dez.burp.aiagent.spi.ExternalBackendSource`,
 * a file only the full JAR carries; the BApp Store build has no such class and no provider, so it
 * never touches [dir].
 *
 * On every registry reload [load] creates [dir] when missing, opens one `URLClassLoader` over the
 * JARs in it (parented on the extension's class loader) and registers every `AiBackendFactory` that
 * loader's `ServiceLoader` finds, as 1.0.1 did. [close] releases that loader, so repeated Settings
 * saves never leak class loaders.
 *
 * A class rather than an `object`: ServiceLoader needs a public no-arg constructor.
 */
class DropInBackendJars internal constructor(
    private val dir: File,
) : ExternalBackendSource {
    constructor() : this(File(System.getProperty("user.home"), DEFAULT_RELATIVE_DIR))

    private var classLoader: URLClassLoader? = null
    private var lastLogError: (String) -> Unit = {}

    /** The class loader the last successful [load] opened, or `null`; for tests. */
    internal val openClassLoader: URLClassLoader?
        @Synchronized get() = classLoader

    @Synchronized
    override fun load(
        parent: ClassLoader,
        log: (String) -> Unit,
        logError: (String) -> Unit,
    ): List<AiBackend> {
        lastLogError = logError
        // The registry calls close() first; closing here as well means a caller that forgets cannot leak.
        close()
        return loadExternalBackendJars(parent, log, logError)
    }

    @Synchronized
    override fun close() {
        val cl = classLoader ?: return
        classLoader = null
        try {
            cl.close()
        } catch (e: IOException) {
            lastLogError("Failed closing backend classloader: ${e.message}")
        }
    }

    /**
     * The body moved from core in phase 31: lists the JARs, loads their factories, remembers the loader.
     *
     * TooGenericExceptionCaught is suppressed because a drop-in JAR is third-party code and its factory
     * may throw anything; a broken JAR is logged and skipped, it must not abort the registry reload.
     */
    @Suppress("TooGenericExceptionCaught")
    internal fun loadExternalBackendJars(
        parent: ClassLoader,
        log: (String) -> Unit,
        logError: (String) -> Unit,
    ): List<AiBackend> {
        dir.mkdirs()
        val jars = dir.listFiles { f -> f.isFile && f.extension.lowercase() == "jar" }?.toList().orEmpty()
        if (jars.isEmpty()) return emptyList()

        val cl = URLClassLoader(jars.map { it.toURI().toURL() }.toTypedArray(), parent)
        return try {
            val created = ServiceLoader.load(AiBackendFactory::class.java, cl).map { it.create() }
            classLoader = cl
            log("Loaded external backend JARs: ${jars.joinToString { it.name }}")
            created
        } catch (e: Exception) {
            closeAfterFailure(cl, e, logError)
        } catch (e: ServiceConfigurationError) {
            // A services entry naming a missing or unloadable class is an Error, not an Exception.
            closeAfterFailure(cl, e, logError)
        }
    }

    private fun closeAfterFailure(
        cl: URLClassLoader,
        failure: Throwable,
        logError: (String) -> Unit,
    ): List<AiBackend> {
        try {
            cl.close()
        } catch (_: IOException) {
        }
        logError("Failed loading external backend JARs: ${failure.message}")
        return emptyList()
    }

    private companion object {
        const val DEFAULT_RELATIVE_DIR = ".burp-ai-agent/backends"
    }
}
