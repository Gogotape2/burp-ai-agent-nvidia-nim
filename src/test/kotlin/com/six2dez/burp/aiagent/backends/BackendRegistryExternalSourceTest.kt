package com.six2dez.burp.aiagent.backends

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import com.six2dez.burp.aiagent.spi.ExternalBackendSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeast
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Phase 31 / D-14 (GATE-04), gap closure WR-06: one failing [ExternalBackendSource], at load or at
 * close, must not abort a registry reload or an extension unload, and the built-in backends stay
 * registered. Registry-level coverage for threat T-31-22 (the 31-SECURITY auditor note). Only a
 * LinkageError is swallowed among the Errors: a VirtualMachineError still propagates.
 */
class BackendRegistryExternalSourceTest {
    private val api = mock<MontoyaApi>()
    private val logging = mock<Logging>()

    init {
        whenever(api.logging()).thenReturn(logging)
    }

    @Test
    fun aSourceWhoseLoadFailsToLinkIsLoggedAndTheBuiltInsStayRegistered() {
        val source = LoadThrowingSource(NoClassDefFoundError(MISSING_CLASS))

        val registry = BackendRegistry(api, listOf(source))

        assertEquals(STORE_IDS, registry.listAllBackendIds().toSet())
        assertEquals(
            listOf("External backend source ${source.javaClass.name} failed: $MISSING_CLASS"),
            errorLines(),
        )
    }

    @Test
    fun aSourceAfterOneThatFailsToLinkStillLoads() {
        val failing = LoadThrowingSource(NoClassDefFoundError(MISSING_CLASS))
        val working = WorkingSource()

        val registry = BackendRegistry(api, listOf(failing, working))

        assertEquals(STORE_IDS + StubBackend.ID, registry.listAllBackendIds().toSet())
    }

    @Test
    fun aSourceWhoseCloseFailsToLinkCannotAbortAReloadOrAnUnload() {
        val source = CloseThrowingSource(NoSuchMethodError("close"))

        // Construction runs reload(), which closes every source before loading it.
        val registry = BackendRegistry(api, listOf(source))
        registry.reload()
        registry.shutdown()

        val expected = "External backend source ${source.javaClass.name} failed: close"
        assertEquals(listOf(expected, expected, expected), errorLines(), "construction, reload and shutdown each log")
    }

    @Test
    fun aSourceWhoseLoadThrowsAnExceptionIsStillLoggedAndSkipped() {
        val source = LoadThrowingSource(IllegalStateException("broken"))

        val registry = BackendRegistry(api, listOf(source))

        assertEquals(STORE_IDS, registry.listAllBackendIds().toSet())
        assertEquals(listOf("External backend source ${source.javaClass.name} failed: broken"), errorLines())
    }

    @Test
    fun aJvmFailureFromASourceStillPropagates() {
        val oom = OutOfMemoryError("test")
        val source = LoadThrowingSource(oom)

        val thrown = assertThrows(OutOfMemoryError::class.java) { BackendRegistry(api, listOf(source)) }

        assertSame(oom, thrown, "the catch is LinkageError, not Error or Throwable")
    }

    private fun errorLines(): List<String> {
        val captor = argumentCaptor<String>()
        verify(logging, atLeast(0)).logToError(captor.capture())
        return captor.allValues
    }

    private class LoadThrowingSource(
        private val failure: Throwable,
    ) : ExternalBackendSource {
        override fun load(
            parent: ClassLoader,
            log: (String) -> Unit,
            logError: (String) -> Unit,
        ): List<AiBackend> = throw failure

        override fun close() = Unit
    }

    private class CloseThrowingSource(
        private val failure: Throwable,
    ) : ExternalBackendSource {
        override fun load(
            parent: ClassLoader,
            log: (String) -> Unit,
            logError: (String) -> Unit,
        ): List<AiBackend> = emptyList()

        override fun close(): Unit = throw failure
    }

    private class WorkingSource : ExternalBackendSource {
        override fun load(
            parent: ClassLoader,
            log: (String) -> Unit,
            logError: (String) -> Unit,
        ): List<AiBackend> = listOf(StubBackend())

        override fun close() = Unit
    }

    private class StubBackend : AiBackend {
        override val id: String = ID
        override val displayName: String = "External stub"

        override fun launch(config: BackendLaunchConfig): AgentConnection = error("the stub backend is never launched")

        companion object {
            const val ID = "external-stub"
        }
    }

    private companion object {
        const val MISSING_CLASS = "com/example/RemovedHttpClient"
        val STORE_IDS =
            setOf("burp-ai", "anthropic", "lmstudio", "nvidia-nim", "ollama", "openai-compatible", "perplexity")
    }
}
