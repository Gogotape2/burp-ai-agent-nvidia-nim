package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.config.McpSettings
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * The process environment of a CLI backend: the login-shell PATH capture, the MCP variables a CLI agent
 * uses to reach this extension's MCP server, and the variables that keep a CLI non-interactive.
 *
 * Phase 29 / D-03 / T-29-23: moved out of the core AgentSupervisor so the login-shell PATH capture
 * runs only for a CLI backend, in the full build. HTTP backends never start a process, and the store
 * build does not contain this class.
 */
internal object CliEnvironment {
    private const val PATH_CAPTURE_TIMEOUT_SECONDS = 5L

    private val cachedPathRef = AtomicReference<String?>(null)

    // Moved verbatim from the core AgentSupervisor companion (plan 29-12), where its ReturnCount finding
    // was baselined; ADR-17 forbids re-adding it under the new name, so it is suppressed locally.
    @Suppress("ReturnCount")
    fun buildCliPathStatic(): String {
        cachedPathRef.get()?.let { return it }

        val initialBase = System.getenv("PATH").orEmpty()
        val userHome = System.getProperty("user.home")
        val sep = java.io.File.pathSeparator
        val os = System.getProperty("os.name").lowercase(java.util.Locale.ROOT)
        val isWin = os.contains("win")

        if (isWin) {
            cachedPathRef.compareAndSet(null, initialBase)
            return cachedPathRef.get()!!
        }

        // On Unix (macOS/Linux), Burp often has a truncated PATH if not started from terminal.
        val capturedPath = capturePathFromShells() ?: initialBase

        // Merge everything and inject common local folders that are often missed
        val rawList = (capturedPath.split(sep) + initialBase.split(sep)).toMutableList()

        val commonFolders =
            listOf(
                "~/.local/bin",
                "~/bin",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            )

        for (f in commonFolders) {
            val expanded = expandHome(f, userHome)
            if (java.io.File(expanded).exists()) {
                rawList.add(expanded)
            }
        }

        val finalPath = rawList.filter { it.isNotBlank() }.distinct().joinToString(sep)

        // Atomic set — first thread wins, subsequent calls use the cached value
        cachedPathRef.compareAndSet(null, finalPath)
        return cachedPathRef.get()!!
    }

    /** The MCP variables a CLI agent reads to reach this extension's MCP server; empty when MCP is off. */
    fun mcpEnv(mcpSettings: McpSettings?): Map<String, String> =
        if (mcpSettings != null && mcpSettings.enabled) {
            val url = "http://${mcpSettings.host}:${mcpSettings.port}/mcp"
            mapOf(
                "BURP_MCP_PORT" to mcpSettings.port.toString(),
                "BURP_MCP_HOST" to mcpSettings.host,
                "BURP_MCP_TOKEN" to mcpSettings.token,
                "BURP_MCP_API_URL" to url,
                "MCP_SERVER_URL" to url,
                "MCP_SERVER" to url,
                "MCP_TOKEN" to mcpSettings.token,
            )
        } else {
            emptyMap()
        }

    /** [base] plus the variables that keep an embedded CLI non-interactive and its output uncolored. */
    fun nonInteractiveEnv(base: Map<String, String>): Map<String, String> =
        base +
            mapOf(
                "CI" to "1",
                "TERM" to "dumb",
                "NO_COLOR" to "1",
                "CLICOLOR" to "0",
                "FORCE_COLOR" to "0",
                "BURP_AI_AGENT_EMBEDDED" to "1",
            )

    private fun expandHome(
        path: String,
        home: String,
    ): String =
        if (path.startsWith("~")) {
            home + path.substring(1)
        } else {
            path
        }

    // Moved verbatim from the core AgentSupervisor companion (plan 29-12), where its ReturnCount finding
    // was baselined; ADR-17 forbids re-adding it under the new name, so it is suppressed locally.
    @Suppress("ReturnCount")
    private fun capturePathFromShells(): String? {
        val shells =
            listOf(
                System.getenv("SHELL"),
                "/bin/zsh",
                "/usr/bin/zsh",
                "/bin/bash",
                "/usr/bin/bash",
                "/bin/sh",
            ).filterNotNull().distinct()

        for (shellPath in shells) {
            if (!java.io.File(shellPath).exists()) continue

            // Strategy A: Standard login shell
            val captured = tryCapture(shellPath, listOf("-l", "-c", "echo ___BURP_PATH___\$PATH"))
            if (!captured.isNullOrBlank()) return captured

            // Strategy B: Explicit source (often needed for macOS GUI apps)
            if (shellPath.endsWith("zsh")) {
                val fallback = tryCapture(shellPath, listOf("-c", "source ~/.zshrc 2>/dev/null; echo ___BURP_PATH___\$PATH"))
                if (!fallback.isNullOrBlank()) return fallback
            }
        }
        return null
    }

    // Moved verbatim from the core AgentSupervisor companion (plan 29-12), where its ReturnCount finding
    // was baselined; ADR-17 forbids re-adding it under the new name, so it is suppressed locally.
    @Suppress("ReturnCount")
    private fun tryCapture(
        shellPath: String,
        args: List<String>,
    ): String? {
        try {
            val process = ProcessBuilder(listOf(shellPath) + args).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            if (!process.waitFor(PATH_CAPTURE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return null
            }
            if (process.exitValue() == 0 && output.contains("___BURP_PATH___")) {
                val result = output.substringAfter("___BURP_PATH___").substringBefore("\n").trim()
                if (result.isNotBlank()) {
                    return result
                }
            }
        } catch (_: Exception) {
            // INTENTIONAL: shell PATH capture is best-effort; returns null on failure (fallback to System.getenv)
        }
        return null
    }
}
