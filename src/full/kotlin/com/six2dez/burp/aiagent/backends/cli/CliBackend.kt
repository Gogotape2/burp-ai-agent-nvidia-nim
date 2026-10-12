package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.AgentConnection
import com.six2dez.burp.aiagent.backends.AiBackend
import com.six2dez.burp.aiagent.backends.BackendDiagnostics
import com.six2dez.burp.aiagent.backends.BackendLaunchConfig
import com.six2dez.burp.aiagent.backends.ChatMessage
import com.six2dez.burp.aiagent.backends.HealthCheckResult
import com.six2dez.burp.aiagent.backends.LaunchRequest
import com.six2dez.burp.aiagent.backends.SessionAwareConnection
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.Defaults
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.ArrayDeque
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class CliBackend(
    override val id: String,
    override val displayName: String,
) : AiBackend {
    /** Avoid spamming "Found X CLI" on every isAvailable() call. */
    private val availabilityLogged = AtomicBoolean(false)

    override fun launch(config: BackendLaunchConfig): AgentConnection {
        require(config.command.isNotEmpty()) { "CLI backend requires a command" }
        // REL-04: use the user-configured timeout if provided, otherwise fall back to the shared constant.
        // WR-02: re-coerce at the consumption boundary. BackendLaunchConfig.cliTimeoutSeconds is a plain
        // nullable Int with no invariant — a directly-constructed config (tests / future call sites) could
        // inject 0 or a negative value, yielding waitFor(0) (immediate timeout) or overflow on the
        // wall-clock break. Floor 30s / ceiling 3600s mirrors the AgentSettings persistence clamp so the
        // watchdog never trusts an unvalidated value regardless of how the config was built.
        val timeoutSeconds = (config.cliTimeoutSeconds ?: Defaults.CLI_PROCESS_TIMEOUT_SECONDS).coerceIn(30, 3600)
        return NonInteractiveCliConnection(id, config.command, config.env, config.cliSessionId, timeoutSeconds)
    }

    /**
     * The CLI launch dialect (Phase 29 / D-09), moved out of the core supervisor unchanged: the command
     * the user configured for this id, the captured login-shell PATH, the MCP variables when the MCP
     * server is on, the non-interactive variables, the resumable CLI session and the process timeout.
     */
    override fun launchConfig(request: LaunchRequest): BackendLaunchConfig {
        val settings = request.settings
        val env =
            CliEnvironment.nonInteractiveEnv(
                request.baseEnv +
                    ("PATH" to CliEnvironment.buildCliPathStatic()) +
                    CliEnvironment.mcpEnv(settings?.mcpSettings),
            )
        return BackendLaunchConfig(
            backendId = request.backendId,
            displayName = LAUNCH_DISPLAY_NAMES[id] ?: displayName,
            command = AgentSupervisor.tokenizeCommand(configuredCommand(settings).trim()),
            sessionId = request.sessionId,
            determinismMode = request.determinismMode,
            env = env,
            cliSessionId = request.cliSessionId,
            cliTimeoutSeconds = settings?.cliTimeoutSeconds,
        )
    }

    /** Releases the temp-file registry shared by every CLI backend. Idempotent, so five instances may call it. */
    override fun shutdown() {
        CliTempFileRegistry.shutdown()
    }

    // Without settings (the supervisor before its first applySettings) the default command for the id.
    private fun configuredCommand(settings: AgentSettings?): String =
        when (id) {
            "codex-cli" -> settings?.codexCmd ?: "codex"
            "gemini-cli" -> settings?.geminiCmd ?: "gemini"
            "opencode-cli" -> settings?.opencodeCmd ?: "opencode"
            "claude-cli" -> settings?.claudeCmd ?: "claude"
            "copilot-cli" -> settings?.copilotCmd ?: "copilot"
            else -> ""
        }

    /** A CLI health check is a local process probe (isAvailable), so background polling may run it. */
    override val healthCheckIsLocal: Boolean = true

    /** The 1.0.1 ratios: Claude 3.5 and Gemini 3.7 characters per token; the others use core's 4.0. */
    override val charsPerTokenEstimate: Double?
        get() = CHARS_PER_TOKEN[id]

    /** The 1.0.1 MainTab validation messages, moved here so core names no CLI id (D-09). */
    override fun configurationError(settings: AgentSettings): String? {
        val isWindows = System.getProperty("os.name").lowercase().contains("win")
        return configurationErrorFor(settings, isWindows)
    }

    internal fun configurationErrorFor(
        settings: AgentSettings,
        isWindows: Boolean,
    ): String? {
        val command = configuredCommand(settings)
        if (command.isBlank()) return EMPTY_COMMAND_MESSAGES[id]
        return if (id == "opencode-cli" && isWindows && looksLikeBareExe(command)) OPENCODE_BARE_EXE_HINT else null
    }

    private fun looksLikeBareExe(cmd: String): Boolean {
        val trimmed = cmd.trim()
        if (!trimmed.lowercase().endsWith(".exe")) return false
        return !trimmed.contains("\\") && !trimmed.contains("/")
    }

    override fun isAvailable(settings: com.six2dez.burp.aiagent.config.AgentSettings): Boolean {
        val command =
            when (id) {
                "claude-cli" -> settings.claudeCmd
                "gemini-cli" -> settings.geminiCmd
                "codex-cli" -> settings.codexCmd
                "opencode-cli" -> settings.opencodeCmd
                "copilot-cli" -> settings.copilotCmd
                "ollama" -> settings.ollamaCliCmd
                else -> ""
            }
        if (command.isBlank()) return false
        // Bug #67: share the tokenizer with the supervisor's launch path so isAvailable() and
        // send() agree on argv[0] (Windows backslash-paths must not be split as escape sequences).
        val cmdList = AgentSupervisor.tokenizeCommand(command.trim())
        val env = mapOf("PATH" to CliEnvironment.buildCliPathStatic())
        val resolved = resolveCommand(cmdList, env)
        if (resolved.isEmpty()) return false
        val executable = resolved[0]
        val file = java.io.File(executable)
        val available = file.exists() && file.canExecute()
        if (available && availabilityLogged.compareAndSet(false, true)) {
            com.six2dez.burp.aiagent.backends.BackendDiagnostics
                .log("[Custom AI Agent] Found $displayName: $executable")
        }
        return available
    }

    override fun healthCheck(settings: com.six2dez.burp.aiagent.config.AgentSettings): HealthCheckResult =
        if (isAvailable(settings)) {
            HealthCheckResult.Healthy
        } else {
            HealthCheckResult.Unavailable("CLI command is not resolvable or executable.")
        }

    private companion object {
        // The display names the 1.0.1 supervisor branches gave each CLI launch.
        val LAUNCH_DISPLAY_NAMES =
            mapOf(
                "codex-cli" to "Codex CLI",
                "gemini-cli" to "Gemini CLI",
                "opencode-cli" to "OpenCode CLI",
                "claude-cli" to "Claude Code",
                "copilot-cli" to "Copilot CLI",
            )

        val CHARS_PER_TOKEN = mapOf("claude-cli" to 3.5, "gemini-cli" to 3.7)

        val EMPTY_COMMAND_MESSAGES =
            mapOf(
                "codex-cli" to "Codex command is empty.",
                "gemini-cli" to "Gemini command is empty.",
                "opencode-cli" to "OpenCode command is empty.",
                "claude-cli" to "Claude command is empty.",
                "copilot-cli" to "Copilot command is empty.",
            )

        const val OPENCODE_BARE_EXE_HINT =
            "OpenCode command looks like a bare .exe. If installed via npm, use 'opencode' (without .exe) " +
                "or a full path to opencode.cmd."
    }

    private class NonInteractiveCliConnection(
        private val backendId: String,
        private val baseCommand: List<String>,
        private val env: Map<String, String>,
        initialCliSessionId: String? = null,
        // REL-04: user-configurable CLI process timeout (issue #71)
        private val cliTimeoutSeconds: Int = Defaults.CLI_PROCESS_TIMEOUT_SECONDS,
    ) : SessionAwareConnection {
        private val executor = Executors.newSingleThreadExecutor()
        private val cliSessionIdRef = AtomicReference<String?>(initialCliSessionId)

        override fun cliSessionId(): String? = cliSessionIdRef.get()

        override fun isAlive(): Boolean = true

        override fun send(
            text: String,
            history: List<ChatMessage>?,
            onChunk: (String) -> Unit,
            onComplete: (Throwable?) -> Unit,
            systemPrompt: String?,
            jsonMode: Boolean,
            maxOutputTokens: Int?,
        ) {
            try {
                executor.submit {
                    val historyText = buildCliHistory(history)
                    val finalText = historyText + text
                    val outputFile =
                        if (backendId == "codex-cli") {
                            // REL-07 / SC5: the finally block below is the primary cleanup path; the registry is
                            // a bounded safety net for one case only — a clean Burp quit while this call is in
                            // flight. See CliTempFileRegistry's KDoc for the window it does not close.
                            java.io.File
                                .createTempFile("burp-ai-agent-codex", ".txt")
                                .also { CliTempFileRegistry.register(it) }
                        } else {
                            null
                        }

                    // Build transcript for stateless CLIs
                    val promptToSend: String
                    val promptFile: java.io.File?
                    val combinedText = if (cliSessionIdRef.get() == null) finalText else text
                    if ((backendId == "claude-cli" || backendId == "copilot-cli") &&
                        combinedText.length > Defaults.LARGE_PROMPT_THRESHOLD
                    ) {
                        val tFile = java.io.File.createTempFile("burp_uv_prompt_", ".txt")
                        // REL-07 / SC5: same contract as the codex output file above — the finally block is
                        // primary, this registration is the bounded net for a clean quit mid-call.
                        CliTempFileRegistry.register(tFile)
                        try {
                            // Set restrictive permissions (owner-only read/write)
                            val posixPath = tFile.toPath()
                            try {
                                java.nio.file.Files.setPosixFilePermissions(
                                    posixPath,
                                    setOf(
                                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                                    ),
                                )
                            } catch (_: UnsupportedOperationException) {
                                // INTENTIONAL: non-POSIX filesystem (Windows) does not support POSIX file permissions; skip
                            }
                            tFile.writeText(combinedText)
                        } catch (e: Exception) {
                            // INTENTIONAL: temp file write failed; cleanup and propagate error via onComplete
                            // REL-07 / SC5: this branch returns before the outer finally block, so it is the ONLY
                            // place that can clear this entry. Without it the registry would retain one entry per
                            // failed prompt write for the life of the JVM — the exact unbounded growth D-01 removes.
                            CliTempFileRegistry.deleteAndDeregister(tFile)
                            onComplete(e)
                            return@submit
                        }
                        promptFile = tFile
                        promptToSend = "Please process the instructions and data provided in the following file:\n${tFile.absolutePath}"
                    } else {
                        promptFile = null
                        promptToSend = combinedText
                    }

                    val (cmd, stdinText) = buildCommand(promptToSend, outputFile)
                    var process: Process? = null
                    try {
                        val resolvedCmd = resolveCommand(cmd, env)
                        if (resolvedCmd.isEmpty()) {
                            onComplete(IllegalStateException("CLI executable not found for $backendId"))
                            return@submit
                        }
                        // Bug #68: explicitly redirect stdin so EVERY CLI backend gets an immediate
                        // EOF when no stdin payload is supplied. Without this, Copilot (and any
                        // other interactive CLI) blocks on its first read for 60s until the
                        // wall-clock timeout fires.
                        val isWin =
                            System
                                .getProperty("os.name")
                                .lowercase(java.util.Locale.ROOT)
                                .contains("win")
                        val nullDevice = java.io.File(if (isWin) "NUL" else "/dev/null")
                        process =
                            ProcessBuilder(normalizeWindowsCommand(resolvedCmd))
                                .apply { environment().putAll(env) }
                                .redirectErrorStream(true)
                                .redirectInput(
                                    if (stdinText.isNullOrBlank()) {
                                        ProcessBuilder.Redirect.from(nullDevice)
                                    } else {
                                        ProcessBuilder.Redirect.PIPE
                                    },
                                ).directory(java.io.File(System.getProperty("user.home")))
                                .start()

                        if (!stdinText.isNullOrBlank()) {
                            process.outputStream.bufferedWriter().use { writer ->
                                writer.write(stdinText)
                                writer.newLine()
                            }
                        } else {
                            // redirectInput(NUL|/dev/null) already provided EOF, but closing the
                            // (unused) PIPE handle is harmless and matches the pre-fix semantics.
                            process.outputStream.close()
                        }

                        val rawOutput = CliOutputBuffer()
                        val lastOutputAt =
                            java.util.concurrent.atomic
                                .AtomicLong(0L)
                        val hasOutput =
                            java.util.concurrent.atomic
                                .AtomicBoolean(false)
                        val readerThread =
                            Thread({
                                val reader = BufferedReader(InputStreamReader(process.inputStream))
                                reader.forEachLine { line ->
                                    rawOutput.appendLine(line)
                                    hasOutput.set(true)
                                    lastOutputAt.set(System.currentTimeMillis())
                                }
                            }, "burp-ai-agent-cli-reader")
                        readerThread.isDaemon = true
                        readerThread.start()

                        var terminatedAfterIdle = false
                        if (backendId == "opencode-cli") {
                            val start = System.currentTimeMillis()
                            while (true) {
                                if (process.waitFor(200, TimeUnit.MILLISECONDS)) break
                                val idleMs = System.currentTimeMillis() - lastOutputAt.get()
                                if (hasOutput.get() && idleMs > Defaults.OPENCODE_IDLE_TIMEOUT_MS) {
                                    terminatedAfterIdle = true
                                    process.destroyForcibly()
                                    break
                                }
                                // REL-04: use the user-configured timeout for the wall-clock safety break
                                if (System.currentTimeMillis() - start > cliTimeoutSeconds * 1000L) break
                            }
                        } else {
                            // REL-04: read user-configured cliTimeoutSeconds instead of hardcoded constant
                            if (!process.waitFor(cliTimeoutSeconds.toLong(), TimeUnit.SECONDS)) {
                                process.destroyForcibly()
                                try {
                                    readerThread.join(2000)
                                } catch (_: InterruptedException) {
                                    // INTENTIONAL: interrupted while waiting for reader thread; restores interrupt flag
                                    Thread.currentThread().interrupt()
                                }
                                val tail = rawOutput.snapshot().trim().take(2000)
                                onComplete(IllegalStateException(buildTimeoutMessage(tail, cliTimeoutSeconds)))
                                return@submit
                            }
                        }
                        try {
                            readerThread.join(2000)
                        } catch (_: InterruptedException) {
                            // INTENTIONAL: interrupted while waiting for reader thread after timeout; restores interrupt flag
                            Thread.currentThread().interrupt()
                        }
                        if (!terminatedAfterIdle && process.exitValue() != 0) {
                            val tail = rawOutput.snapshot().trim().take(2000)
                            val msg =
                                if (tail.isBlank()) {
                                    "CLI command failed (exit=${process.exitValue()})"
                                } else {
                                    "CLI command failed (exit=${process.exitValue()}): $tail"
                                }
                            onComplete(IllegalStateException(msg))
                            return@submit
                        }

                        val stdoutText = stripAnsiCodes(rawOutput.snapshot())
                        val finalMessage =
                            when (backendId) {
                                "codex-cli" -> readCodexOutput(outputFile, stdoutText, text)
                                "gemini-cli" -> readGeminiOutput(stdoutText, text)
                                "opencode-cli" -> readOpenCodeOutput(stdoutText, text)
                                "claude-cli" -> readClaudeOutput(stdoutText, text)
                                "copilot-cli" -> readCopilotOutput(stdoutText, text)
                                else -> stdoutText.trim()
                            }
                        if (finalMessage.isNotBlank()) onChunk(finalMessage)
                        onComplete(null)
                    } catch (e: Exception) {
                        // INTENTIONAL: CLI process launch/execution error; propagated via onComplete
                        onComplete(e)
                    } finally {
                        // Guaranteed cleanup: kill process, delete temp files
                        try {
                            process?.destroyForcibly()
                        } catch (_: Exception) {
                            // INTENTIONAL: finally block cleanup; destroyForcibly() must not prevent file cleanup
                        }
                        try {
                            // REL-07 / SC5: the entry is dropped only once the file is gone. File.delete() reports
                            // failure by returning false, and returns false on Windows while the CLI child still
                            // holds the handle; a surviving entry is what lets the registry's drain retry.
                            CliTempFileRegistry.deleteAndDeregister(promptFile)
                        } catch (_: Exception) {
                            // INTENTIONAL: finally block cleanup; file deletion must not prevent process cleanup
                        }
                        try {
                            CliTempFileRegistry.deleteAndDeregister(outputFile)
                        } catch (_: Exception) {
                            // INTENTIONAL: finally block cleanup; file deletion must not prevent process cleanup
                        }
                    }
                }
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                // INTENTIONAL: executor shut down; propagate shutdown state via onComplete
                onComplete(IllegalStateException("Backend connection has been stopped", e))
            }
        }

        override fun stop() {
            executor.shutdownNow()
            try {
                executor.awaitTermination(3, TimeUnit.SECONDS)
            } catch (_: InterruptedException) {
                // INTENTIONAL: interrupted during executor shutdown; restores interrupt flag
                Thread.currentThread().interrupt()
            }
        }

        private fun buildCommand(
            prompt: String,
            outputFile: java.io.File?,
        ): Pair<List<String>, String?> =
            when (backendId) {
                "codex-cli" -> {
                    val cmd = buildCodexExecCommand(baseCommand, outputFile)
                    cmd to prompt
                }
                "gemini-cli" -> {
                    val cmd = buildGeminiCommand(baseCommand)
                    cmd to prompt
                }
                "opencode-cli" -> {
                    val cmd = buildOpenCodeCommand(baseCommand, prompt)
                    cmd to null
                }
                "claude-cli" -> {
                    val cmd = buildClaudeCommand(baseCommand)
                    cmd to prompt
                }
                "copilot-cli" -> {
                    // Bug #68: pass the prompt as a positional value for `-p` so Copilot runs
                    // non-interactively (no menu, no 60s wall-clock hang). stdin is left
                    // unconnected — the explicit redirectInput(NUL|/dev/null) below provides EOF.
                    val cmd = buildCopilotCommand(baseCommand, prompt)
                    cmd to null
                }
                else -> baseCommand to prompt
            }

        private fun buildCodexExecCommand(
            cmd: List<String>,
            outputFile: java.io.File?,
        ): List<String> {
            val base = cmd.firstOrNull() ?: "codex"
            val extras = cmd.drop(1)
            val hasExec = extras.contains("exec")
            val filtered = extras.filterNot { it == "chat" }
            val args = mutableListOf<String>()
            args.add(base)
            if (hasExec) {
                args.addAll(filtered)
            } else {
                args.add("exec")
                args.add("--color")
                args.add("never")
                args.add("--skip-git-repo-check")
                args.addAll(filtered)
            }
            if (outputFile != null && !args.contains("--output-last-message")) {
                args.add("--output-last-message")
                args.add(outputFile.absolutePath)
            }
            if (!args.contains("-")) {
                args.add("-")
            }
            return args
        }

        private fun buildGeminiCommand(cmd: List<String>): List<String> {
            val base = cmd.firstOrNull() ?: "gemini"
            val extras = filterGeminiPromptFlags(cmd.drop(1))
            val args = mutableListOf<String>()
            args.add(base)
            args.addAll(extras)
            if (!args.contains("--output-format")) {
                args.add("--output-format")
                args.add("text")
            }
            if (!args.contains("-p") && !args.contains("--prompt")) {
                args.add("-p")
                args.add(".")
            }
            return args
        }

        private fun filterGeminiPromptFlags(args: List<String>): List<String> {
            val filtered = mutableListOf<String>()
            var skipNext = false
            for (arg in args) {
                if (skipNext) {
                    skipNext = false
                    continue
                }
                if (arg == "-p" || arg == "--prompt" || arg == "-i" || arg == "--prompt-interactive") {
                    skipNext = true
                    continue
                }
                filtered.add(arg)
            }
            return filtered
        }

        private fun readCodexOutput(
            outputFile: java.io.File?,
            stdout: String,
            prompt: String,
        ): String {
            val fileText =
                outputFile
                    ?.takeIf { it.exists() }
                    ?.readText()
                    ?.trim()
                    .orEmpty()
            if (fileText.isNotBlank()) return fileText
            val inputLines =
                prompt
                    .lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }

        private fun readGeminiOutput(
            stdout: String,
            prompt: String,
        ): String {
            val inputLines =
                prompt
                    .lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .filterNot { isGeminiNoiseLine(it) }
                .joinToString("\n")
                .trim()
        }

        private fun isGeminiNoiseLine(line: String): Boolean {
            val lower = line.lowercase()
            return lower == "loaded cached credentials." ||
                lower.startsWith("mcp server 'burp':") ||
                lower.startsWith("error during discovery for mcp server") ||
                lower.startsWith("hook registry initialized with") ||
                (lower.startsWith("error executing tool ") && lower.contains("tool execution denied by policy")) ||
                lower.startsWith("loading extension:") ||
                lower.startsWith("listening for changes") ||
                lower.contains("supports tool updates") ||
                (lower.startsWith("ready.") && lower.contains("standing by")) ||
                lower.startsWith("send over your first target")
        }

        private fun buildOpenCodeCommand(
            cmd: List<String>,
            prompt: String,
        ): List<String> {
            val base = cmd.firstOrNull() ?: "opencode"
            val extras = cmd.drop(1)
            val args = mutableListOf<String>()
            args.add(base)
            args.add("run")
            args.addAll(extras)
            args.add(prompt)
            return args
        }

        private fun readOpenCodeOutput(
            stdout: String,
            prompt: String,
        ): String {
            // Only dedup long prompt lines (>=40 chars) — short lines match real content too often
            val inputLines =
                prompt
                    .lines()
                    .map { it.trim() }
                    .filter { it.length >= 40 }
                    .toSet()
            return stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .filterNot { isOpenCodeNoiseLine(it) }
                .joinToString("\n")
                .trim()
        }

        private fun isOpenCodeNoiseLine(line: String): Boolean {
            val lower = line.lowercase()
            // All short "> " prefixed lines are OpenCode status/metadata
            if (lower.startsWith("> ") && line.length < 120) return true
            // Version banners and session IDs
            if (lower.startsWith("opencode v") || lower.startsWith("session:")) return true
            return false
        }

        private fun buildClaudeCommand(cmd: List<String>): List<String> {
            val base = cmd.firstOrNull() ?: "claude"
            val extras = cmd.drop(1)
            val args = mutableListOf<String>()
            args.add(base)
            args.addAll(extras)
            if (!args.contains("-p") && !args.contains("--print")) {
                args.add("-p")
            }
            val currentSessionId = cliSessionIdRef.get()
            if (currentSessionId != null) {
                // Follow-up message: resume existing conversation
                args.add("--resume")
                args.add(currentSessionId)
            } else {
                // First message: generate a new session id (atomic CAS to avoid races)
                val newId =
                    java.util.UUID
                        .randomUUID()
                        .toString()
                if (cliSessionIdRef.compareAndSet(null, newId)) {
                    args.add("--session-id")
                    args.add(newId)
                } else {
                    // Another thread won the race — resume their session
                    args.add("--resume")
                    args.add(
                        cliSessionIdRef.get()
                            ?: error("CLI session ID lost between CAS and read"),
                    )
                }
            }
            return args
        }

        private fun readClaudeOutput(
            stdout: String,
            prompt: String,
        ): String {
            val inputLines =
                prompt
                    .lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }

        private fun readCopilotOutput(
            stdout: String,
            prompt: String,
        ): String {
            val inputLines =
                prompt
                    .lines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .toSet()
            return stdout
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotBlank() && !inputLines.contains(it) }
                .joinToString("\n")
                .trim()
        }
    }
}

/**
 * Issue #71 — Build an actionable timeout message for the CLI process watchdog (REL-04).
 *
 * The message names the configured limit and suggests how to fix it so users know what to do
 * when a CLI (e.g. `npx @google/gemini-cli` first-run download) exceeds the timeout.
 *
 * Privacy guarantee: only [tail] is interpolated and it is already bounded by the caller's
 * `take(2000)` discipline — prompt/context content is never interpolated here.
 *
 * Visibility: `internal` so CliTimeoutMessageTest can call it directly (same pattern as
 * buildCopilotCommand / CopilotCommandBuilderTest). Not part of the public API.
 */
internal fun buildTimeoutMessage(
    tail: String,
    timeoutSeconds: Int,
): String {
    val remedy =
        "To fix: increase the cliTimeoutSeconds setting, or pre-install the CLI tool " +
            "so it does not need to download on first run."
    return if (tail.isBlank()) {
        "CLI command timed out after ${timeoutSeconds}s. $remedy"
    } else {
        "CLI command timed out after ${timeoutSeconds}s: $tail. $remedy"
    }
}

/**
 * Bug #68 — Build the argv for the `copilot-cli` backend so the CLI runs non-interactively.
 *
 * Guarantees:
 *  - argv[0] is `base` (the user-supplied executable, defaults to `copilot`).
 *  - `--no-color` and `--silent` appear BEFORE any auto-injected `-p <prompt>`.
 *  - The prompt is appended as `-p <prompt>` only when the user did not already supply `-p` or
 *    `--prompt` in their `extras`; in that case the helper does NOT add a second prompt flag.
 *  - Legacy `--quiet` is stripped from extras to avoid passing an unsupported Copilot CLI flag.
 *  - User-supplied `--no-color` and `--silent`/`-s` are NOT duplicated.
 *  - User-supplied extras flow through in their original relative order, after the auto-injected
 *    flags and before the auto-injected `-p` value.
 *
 * Visibility: `internal` (module-scoped) so the test in `src/test/kotlin/.../cli/CopilotCommandBuilderTest.kt`
 * can call it directly without reflection. Not part of the backend's public surface.
 */
internal fun buildCopilotCommand(
    cmd: List<String>,
    prompt: String,
): List<String> {
    val base = cmd.firstOrNull() ?: "copilot"
    val extras = cmd.drop(1).filterNot { it == "--quiet" }
    val args = mutableListOf<String>()
    args.add(base)
    if (!extras.contains("--no-color")) args.add("--no-color")
    if (!extras.contains("--silent") && !extras.contains("-s")) args.add("--silent")
    args.addAll(extras)
    if (!extras.contains("-p") && !extras.contains("--prompt")) {
        args.add("-p")
        args.add(prompt)
    }
    return args
}

/**
 * Windows launch fix-ups: strip a redundant `.exe`, resolve a non-executable npm shim next to an
 * absolute path, or find the `.cmd` shim npm installed for a bare command name.
 *
 * [windows] is a defaulted parameter purely so both branches can be asserted on one machine;
 * production calls this with no explicit argument, so its behaviour is unchanged. The alternative — mutating the global `os.name` system property from a
 * test — would leak into every other test sharing the JVM.
 *
 * Visibility: `internal` so CliCommandHelpersTest can call it directly (same pattern as
 * buildTimeoutMessage / buildCopilotCommand). Not part of the public API.
 */
internal fun normalizeWindowsCommand(
    cmd: List<String>,
    windows: Boolean = isWindowsOs,
): List<String> {
    if (!windows || cmd.isEmpty()) return cmd
    val first = cmd.first()
    val lower = first.lowercase(Locale.ROOT)
    val rest = cmd.drop(1)
    return when {
        // Strip redundant .exe suffix
        lower.endsWith(".exe") -> listOf(first.dropLast(WINDOWS_EXTENSION_LENGTH)) + rest
        // For absolute paths: check if it's a non-executable npm shim
        first.contains("\\") || first.contains("/") -> {
            val file = java.io.File(first)
            if (file.isAbsolute && file.exists() && !hasWindowsExeExtension(lower)) {
                val cmdSibling = java.io.File(first + ".cmd")
                // Fallback when there is no .cmd sibling: wrap with cmd /c for shell script shims
                if (cmdSibling.exists()) {
                    listOf(cmdSibling.absolutePath) + rest
                } else {
                    listOf("cmd", "/c", first) + rest
                }
            } else {
                cmd
            }
        }
        // For bare command names: resolve npm .cmd shim
        else -> {
            val baseName = if (lower.endsWith(".cmd")) lower.dropLast(WINDOWS_EXTENSION_LENGTH) else lower
            windowsNpmShimDirs
                .map { java.io.File(it, "$baseName.cmd") }
                .firstOrNull { it.exists() }
                ?.let { listOf(it.absolutePath) + rest }
                ?: cmd
        }
    }
}

/** Length of the `.exe` / `.cmd` / `.bat` suffixes [normalizeWindowsCommand] strips. */
private const val WINDOWS_EXTENSION_LENGTH = 4

/**
 * Whether [path] already names a directly executable Windows file, i.e. one that needs no `cmd /c`
 * wrapper or `.cmd` shim lookup.
 *
 * Visibility: `internal` so CliCommandHelpersTest can call it directly (same pattern as
 * buildTimeoutMessage / buildCopilotCommand). Not part of the public API.
 */
internal fun hasWindowsExeExtension(path: String): Boolean {
    val l = path.lowercase(Locale.ROOT)
    return l.endsWith(".exe") || l.endsWith(".cmd") || l.endsWith(".bat")
}

/** Most recent turns of chat history a CLI prompt carries. */
internal const val CLI_HISTORY_MAX_MESSAGES = 10

/** Total characters of chat history a CLI prompt carries, counted role-prefix included. */
internal const val CLI_HISTORY_MAX_CHARS = 20_000

/**
 * Render [history] as the `role: content` preamble prepended to a CLI prompt, bounded by
 * [CLI_HISTORY_MAX_MESSAGES] and [CLI_HISTORY_MAX_CHARS]. Returns the empty string — not a stray
 * blank line — when there is no history to carry.
 *
 * Visibility: `internal` so CliCommandHelpersTest can call it directly (same pattern as
 * buildTimeoutMessage / buildCopilotCommand). Not part of the public API.
 */
internal fun buildCliHistory(history: List<ChatMessage>?): String {
    if (history.isNullOrEmpty()) return ""
    val limited = limitCliHistory(history, maxMessages = CLI_HISTORY_MAX_MESSAGES, maxChars = CLI_HISTORY_MAX_CHARS)
    return limited.joinToString("\n") { "${it.role}: ${it.content}" } + "\n\n"
}

/**
 * Trim [history] to the most recent [maxMessages] turns, then drop the oldest of those until the
 * total fits [maxChars]. A single turn that alone exceeds [maxChars] is truncated rather than
 * dropped, so the newest message is never lost entirely.
 *
 * Visibility: `internal` so CliCommandHelpersTest can call it directly (same pattern as
 * buildTimeoutMessage / buildCopilotCommand). Not part of the public API.
 */
internal fun limitCliHistory(
    history: List<ChatMessage>,
    maxMessages: Int,
    maxChars: Int,
): List<ChatMessage> {
    if (history.isEmpty()) return emptyList()
    val trimmed = history.takeLast(maxMessages)
    val result = ArrayDeque<ChatMessage>()
    var total = 0
    for (msg in trimmed.asReversed()) {
        val len = msg.role.length + 2 + msg.content.length
        if (total + len > maxChars && result.isNotEmpty()) break
        if (len > maxChars && result.isEmpty()) {
            val slice = msg.content.take(maxChars.coerceAtLeast(1))
            result.addFirst(ChatMessage(msg.role, slice))
            break
        }
        result.addFirst(msg)
        total += len
    }
    return result.toList()
}

private fun resolveCommand(
    cmd: List<String>,
    env: Map<String, String>,
): List<String> {
    if (cmd.isEmpty()) return cmd
    val first = cmd[0]

    // 1. If already an absolute path, verify and return
    val firstFile = java.io.File(first)
    if (firstFile.isAbsolute) {
        return if (firstFile.exists()) {
            cmd
        } else {
            com.six2dez.burp.aiagent.backends.BackendDiagnostics
                .log("[Custom AI Agent] Absolute path not found: $first")
            emptyList()
        }
    }

    // 2. Manual PATH search to avoid dependency on 'which' / 'where'
    val path = env["PATH"] ?: System.getenv("PATH") ?: ""
    val sep = java.io.File.pathSeparator
    val isWin = isWindowsOs
    val extensions = if (isWin) listOf("", ".exe", ".bat", ".cmd") else listOf("")

    for (dir in path.split(sep)) {
        if (dir.isBlank()) continue
        for (ext in extensions) {
            val candidate = java.io.File(dir, first + ext)
            try {
                if (candidate.exists() && candidate.canExecute()) {
                    return listOf(candidate.absolutePath) + cmd.drop(1)
                }
            } catch (_: Exception) {
                // INTENTIONAL: unreadable PATH directory; skip silently to avoid aborting full PATH search
            }
        }
    }

    return emptyList()
}

/**
 * Whether this JVM is running on Windows.
 *
 * Read once rather than per call: `os.name` is fixed for the lifetime of a JVM, and no test in this
 * module mutates it (the one test that consults it, CliSupervisionTest, only reads it to skip).
 */
private val isWindowsOs: Boolean = System.getProperty("os.name").lowercase(Locale.ROOT).contains("win")

/**
 * The directories npm installs its `.cmd` shims into on Windows, in resolution order.
 *
 * Previously computed inside a `resolveWindowsNpmShim(executable)` function on every call. The
 * directories derive from environment variables, which a JVM cannot see change after start, so the
 * list is built once and the per-call work is reduced to the `.cmd` lookup at the call site. Empty
 * on every non-Windows machine, where none of the three variables is set.
 */
private val windowsNpmShimDirs: List<java.io.File> =
    listOfNotNull(
        System.getenv("APPDATA")?.takeIf { it.isNotBlank() }?.let { java.io.File(it, "npm") },
        System.getenv("LOCALAPPDATA")?.takeIf { it.isNotBlank() }?.let { java.io.File(it, "npm") },
        System.getenv("USERPROFILE")?.takeIf { it.isNotBlank() }?.let { java.io.File(it, "AppData\\Roaming\\npm") },
    )

/**
 * Remove terminal control sequences from CLI output so the rendered answer carries no escape bytes.
 *
 * Visibility: `internal` so CliCommandHelpersTest can call it directly (same pattern as
 * buildTimeoutMessage / buildCopilotCommand). Not part of the public API.
 */
internal fun stripAnsiCodes(text: String): String {
    if (text.isEmpty()) return text

    var result = text

    // Strip all ANSI escape sequences
    // CSI sequences: ESC [ ... letter (e.g., \u001B[0m, \u001B[1;31m)
    result = result.replace(Regex("\\u001B\\[[0-9;]*[a-zA-Z]"), "")

    // OSC sequences: ESC ] ... BEL (e.g., \u001B]0;title\u0007)
    result = result.replace(Regex("\\u001B\\][^\\u0007]*\\u0007"), "")

    // Other escape sequences (e.g., \u001B>, \u001B=)
    result = result.replace(Regex("\\u001B[><=][^\\u0007\\u001B\\\\]*[\\u0007\\u001B\\\\]"), "")

    // Strip any remaining literal ANSI-like patterns (e.g., "[0m", "[1m")
    result = result.replace(Regex("\\[\\d+m"), "")

    return result
}
