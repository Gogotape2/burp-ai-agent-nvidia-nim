package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.util.ShutdownDeadline
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

// RED skeleton (Phase 33 plan 03, Task 3): signatures only.
internal object McpCoroutines {
    const val MCP_COROUTINE_THREADS = 64

    fun dispatcher(): CoroutineDispatcher = Dispatchers.Unconfined

    fun close(
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
    ) = Unit

    internal fun shouldShutdownShared(
        dispatchersLoader: ClassLoader?,
        extensionLoader: ClassLoader?,
    ): Boolean = true

    fun shutdownSharedDispatchers(
        deadline: ShutdownDeadline,
        logError: (String) -> Unit,
    ) = Unit
}
