package com.six2dez.burp.aiagent.full.cli

import burp.api.montoya.MontoyaApi
import java.awt.Component
import javax.swing.JOptionPane

/**
 * Phase 29 / D-07, T-29-27 — the "Open CLI" terminal launcher, moved verbatim from the core settings
 * panel into the full build. The store JAR carries no code that spawns a terminal from the settings
 * window; `CoreBackendNamesGuardTest` keeps it out of `src/main`.
 *
 * Opens a new terminal window running the user-configured [command]: `cmd.exe /k` on Windows,
 * Terminal.app through `osascript` on macOS, and the first available of x-terminal-emulator,
 * gnome-terminal, konsole and xterm elsewhere. EDT (it may show a dialog).
 */
internal object CliTerminalLauncher {
    // TooGenericExceptionCaught: ProcessBuilder.start throws IOException, SecurityException and others;
    // every failure becomes the same 1.0.1 error dialog.
    @Suppress("TooGenericExceptionCaught")
    fun openExternalCli(
        api: MontoyaApi,
        dialogParent: Component?,
        backendId: String,
        command: String,
    ) {
        if (command.isBlank()) {
            JOptionPane.showMessageDialog(
                dialogParent,
                "Command is empty for $backendId.",
                "Custom AI Agent",
                JOptionPane.WARNING_MESSAGE,
            )
            return
        }
        try {
            val os = System.getProperty("os.name").lowercase()
            val process =
                when {
                    os.contains("win") -> {
                        ProcessBuilder("cmd.exe", "/c", "start", "\"AI Agent CLI\"", "cmd.exe", "/k", command)
                    }
                    os.contains("mac") -> {
                        val escaped = command.replace("\\", "\\\\").replace("\"", "\\\"")
                        ProcessBuilder("osascript", "-e", "tell application \"Terminal\" to do script \"$escaped\"")
                    }
                    else -> {
                        val shellCmd =
                            "x-terminal-emulator -e bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| gnome-terminal -- bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| konsole -e bash -lc ${shellQuote("$command; exec bash")} " +
                                "|| xterm -e bash -lc ${shellQuote("$command; exec bash")}"
                        ProcessBuilder("sh", "-c", shellCmd)
                    }
                }
            process.start()
        } catch (e: Exception) {
            api.logging().logToError("Failed to open CLI for $backendId: ${e.message}")
            JOptionPane.showMessageDialog(
                dialogParent,
                "Failed to open CLI: ${e.message}",
                "Custom AI Agent",
                JOptionPane.ERROR_MESSAGE,
            )
        }
    }

    // ReturnCount: the 1.0.1 body, moved verbatim from SettingsPanelActions (where it was baselined).
    @Suppress("ReturnCount")
    internal fun shellQuote(value: String): String {
        if (value.isEmpty()) return "''"
        if (value.none { it.isWhitespace() || it == '"' || it == '\'' }) return value
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }
}
