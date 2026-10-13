package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.backends.ChatMessage
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

/**
 * Phase 26 SC2 / QUAL-06 — behavioural coverage for the pure command / history / ANSI helpers in
 * `CliBackend.kt`.
 *
 * Every test here asserts on a result. None of them calls production code merely to move a jacoco
 * counter: a coverage number bought with assertion-free calls is worse than the uncovered line it
 * replaces, because it reports the code as guarded when nothing guards it.
 *
 * Three deliberate exclusions, recorded so the gap is a decision rather than an oversight:
 *  - `resolveCommand` walks `PATH` and stats the filesystem, so a test over it asserts the shape of
 *    the developer's machine rather than the behaviour of the code.
 *  - `isWindowsOs` and `windowsNpmShimDirs` read process-lifetime-constant JVM inputs; there is no
 *    seam to drive them and nothing to assert beyond the JVM's own answer.
 *
 * The Windows branch of [normalizeWindowsCommand] is reached through its defaulted `windows`
 * parameter rather than by mutating the global `os.name` system property, which would leak into
 * every other test sharing the JVM. No test here compares an elapsed duration to a threshold.
 */
class CliCommandHelpersTest {
    /**
     * ASCII ESC (0x1B), the byte every ANSI control sequence opens with. Written as a code point
     * rather than as a literal control character so the fixtures below stay readable in a diff.
     */
    private val esc = 27.toChar()

    // ---- normalizeWindowsCommand ----

    @Test
    fun nonWindowsArgvIsReturnedUntouched() {
        val cmd = listOf("claude", "-p", "hello")
        assertEquals(cmd, normalizeWindowsCommand(cmd, windows = false), "the non-Windows path must be a no-op")
    }

    @Test
    fun productionDefaultIsANoOpOnThisNonWindowsMachine() {
        // Guards the defaulted parameter itself: production calls normalizeWindowsCommand(cmd) with
        // no explicit flag, and on a non-Windows JVM that must still take the no-op path.
        val cmd = listOf("claude", "-p", "hello")
        val normalized = normalizeWindowsCommand(cmd)
        val runningOnWindows = System.getProperty("os.name").lowercase().contains("win")
        if (!runningOnWindows) {
            assertEquals(cmd, normalized, "on a non-Windows JVM the default parameter must select the no-op path")
        }
    }

    @Test
    fun emptyArgvIsReturnedUntouchedEvenOnWindows() {
        assertEquals(
            emptyList<String>(),
            normalizeWindowsCommand(emptyList(), windows = true),
            "an empty argv has no executable to normalize",
        )
    }

    @Test
    fun redundantExeSuffixIsStripped() {
        assertEquals(
            listOf("claude", "-p"),
            normalizeWindowsCommand(listOf("claude.exe", "-p"), windows = true),
            "ProcessBuilder resolves 'claude' on Windows, so the redundant .exe is dropped",
        )
    }

    @Test
    fun exeSuffixStripPreservesTheCaseOfTheRemainingName() {
        assertEquals(
            listOf("CLAUDE", "-p"),
            normalizeWindowsCommand(listOf("CLAUDE.EXE", "-p"), windows = true),
            "the extension test is case-insensitive but the surviving name is taken from the original argv",
        )
    }

    @Test
    fun relativePathWithSeparatorIsReturnedUntouched() {
        val cmd = listOf("tools/claude", "-p")
        assertEquals(
            cmd,
            normalizeWindowsCommand(cmd, windows = true),
            "only ABSOLUTE paths are candidates for shim resolution; a relative one is left alone",
        )
    }

    @Test
    fun absolutePathWithNoExecutableExtensionIsWrappedWithCmdSlashC(
        @TempDir tempDir: File,
    ) {
        val shim = File(tempDir, "claude")
        shim.writeText("#!/bin/sh\n")
        assertEquals(
            listOf("cmd", "/c", shim.absolutePath, "-p"),
            normalizeWindowsCommand(listOf(shim.absolutePath, "-p"), windows = true),
            "an existing extensionless absolute path is a shell-script shim and needs the cmd /c wrapper",
        )
    }

    @Test
    fun absolutePathPrefersAnAdjacentCmdShim(
        @TempDir tempDir: File,
    ) {
        val shim = File(tempDir, "claude")
        shim.writeText("#!/bin/sh\n")
        val cmdSibling = File(tempDir, "claude.cmd")
        cmdSibling.writeText("@echo off\n")
        assertEquals(
            listOf(cmdSibling.absolutePath, "-p"),
            normalizeWindowsCommand(listOf(shim.absolutePath, "-p"), windows = true),
            "a .cmd sibling is directly executable, so it beats the cmd /c fallback",
        )
    }

    @Test
    fun absolutePathThatAlreadyHasAnExecutableExtensionIsLeftAlone(
        @TempDir tempDir: File,
    ) {
        val exe = File(tempDir, "claude.bat")
        exe.writeText("@echo off\n")
        val cmd = listOf(exe.absolutePath, "-p")
        assertEquals(
            cmd,
            normalizeWindowsCommand(cmd, windows = true),
            "a .bat is already directly executable and must not be wrapped or re-resolved",
        )
    }

    // ---- hasWindowsExeExtension ----

    @Test
    fun theThreeDirectlyExecutableWindowsExtensionsAreRecognised() {
        for (name in listOf("claude.exe", "claude.cmd", "claude.bat")) {
            assertTrue(hasWindowsExeExtension(name), "$name names a directly executable Windows file")
        }
    }

    @Test
    fun extensionTestIsCaseInsensitive() {
        assertTrue(hasWindowsExeExtension("CLAUDE.EXE"), "Windows paths are case-insensitive, so the test must be too")
    }

    @Test
    fun bareNameAndLookalikeExtensionAreNotExecutable() {
        assertFalse(hasWindowsExeExtension("claude"), "a bare name carries no extension")
        assertFalse(hasWindowsExeExtension("claude.exec"), "'.exec' is a lookalike, not one of the three extensions")
        assertFalse(hasWindowsExeExtension("claude.com"), "'.com' is not in the list the implementation accepts")
    }

    // ---- buildCliHistory ----

    @Test
    fun nullHistoryProducesNoPreamble() {
        assertEquals("", buildCliHistory(null), "a null history must add nothing, not a stray blank line")
    }

    @Test
    fun emptyHistoryProducesNoPreamble() {
        assertEquals("", buildCliHistory(emptyList()), "an empty history must add nothing")
    }

    @Test
    fun populatedHistoryInterleavesRolesAndEndsWithABlankLine() {
        val history =
            listOf(
                ChatMessage("user", "first question"),
                ChatMessage("assistant", "first answer"),
                ChatMessage("user", "second question"),
            )
        assertEquals(
            "user: first question\nassistant: first answer\nuser: second question\n\n",
            buildCliHistory(history),
            "each turn is one 'role: content' line and the block is separated from the prompt by a blank line",
        )
    }

    // ---- limitCliHistory ----

    @Test
    fun historyUnderBothBoundsIsReturnedWhole() {
        val history = (1..CLI_HISTORY_MAX_MESSAGES).map { ChatMessage("user", "m$it") }
        assertEquals(
            history,
            limitCliHistory(history, CLI_HISTORY_MAX_MESSAGES, CLI_HISTORY_MAX_CHARS),
            "exactly at the message bound and far under the character bound, nothing may be dropped",
        )
    }

    @Test
    fun emptyHistoryIsReturnedEmpty() {
        assertEquals(
            emptyList<ChatMessage>(),
            limitCliHistory(emptyList(), CLI_HISTORY_MAX_MESSAGES, CLI_HISTORY_MAX_CHARS),
            "an empty history has nothing to limit",
        )
    }

    @Test
    fun exceedingTheMessageBoundDropsTheOldestTurns() {
        val extra = 3
        val history = (1..CLI_HISTORY_MAX_MESSAGES + extra).map { ChatMessage("user", "m$it") }
        val limited = limitCliHistory(history, CLI_HISTORY_MAX_MESSAGES, CLI_HISTORY_MAX_CHARS)
        assertEquals(
            CLI_HISTORY_MAX_MESSAGES,
            limited.size,
            "the message bound caps the turn count",
        )
        assertEquals(
            history.takeLast(CLI_HISTORY_MAX_MESSAGES),
            limited,
            "the turns kept are the NEWEST ones; dropping from the wrong end loses the live conversation",
        )
    }

    @Test
    fun exceedingTheCharacterBoundDropsTheOldestTurnsThatDoNotFit() {
        // Four turns of a quarter of the budget each overshoot it, so at least one must be dropped.
        val content = "x".repeat(CLI_HISTORY_MAX_CHARS / 4)
        val history = (1..CLI_HISTORY_MAX_MESSAGES).map { ChatMessage("user", content) }
        val limited = limitCliHistory(history, CLI_HISTORY_MAX_MESSAGES, CLI_HISTORY_MAX_CHARS)

        assertTrue(
            limited.size < history.size,
            "the character bound must bite before the message bound here, got ${limited.size} of ${history.size}",
        )
        assertEquals(
            history.takeLast(limited.size),
            limited,
            "the turns kept are the NEWEST ones",
        )
        val perTurn = "user".length + 2 + content.length
        assertTrue(
            limited.size * perTurn <= CLI_HISTORY_MAX_CHARS,
            "the kept turns must fit the character budget, got ${limited.size * perTurn}",
        )
        assertTrue(
            (limited.size + 1) * perTurn > CLI_HISTORY_MAX_CHARS,
            "one more turn must not have fitted, or the helper dropped more than the budget required",
        )
    }

    @Test
    fun aSingleOversizedTurnIsTruncatedRatherThanDropped() {
        val history = listOf(ChatMessage("user", "x".repeat(CLI_HISTORY_MAX_CHARS * 2)))
        val limited = limitCliHistory(history, CLI_HISTORY_MAX_MESSAGES, CLI_HISTORY_MAX_CHARS)
        assertEquals(1, limited.size, "the newest turn is never lost entirely, even when it alone busts the budget")
        assertEquals(
            CLI_HISTORY_MAX_CHARS,
            limited[0].content.length,
            "an oversized turn is truncated to the character budget",
        )
        assertEquals("user", limited[0].role, "truncation must preserve the role")
    }

    // ---- stripAnsiCodes ----

    @Test
    fun colourSequencesAreRemoved() {
        assertEquals(
            "red",
            stripAnsiCodes("$esc[31mred$esc[0m"),
            "SGR colour sequences must not reach the rendered answer",
        )
    }

    @Test
    fun cursorMovementSequencesAreRemoved() {
        assertEquals(
            "ab",
            stripAnsiCodes("a$esc[2Kb"),
            "line-erase and cursor-movement CSI sequences are stripped by the same rule as colour",
        )
        assertEquals(
            "ab",
            stripAnsiCodes("a$esc[1;1Hb"),
            "a parameterised cursor-position sequence is stripped too",
        )
    }

    @Test
    fun plainTextIsReturnedByteIdentical() {
        val plain = "the answer is 42, see /tmp/report.json"
        assertEquals(plain, stripAnsiCodes(plain), "text with no escape byte must pass through untouched")
    }

    @Test
    fun emptyInputIsReturnedEmpty() {
        assertEquals("", stripAnsiCodes(""), "the empty string has nothing to strip")
    }

    @Test
    fun aBareBracketThatIsNotPartOfAnEscapeSequenceSurvives() {
        assertEquals(
            "array[0] and a[b",
            stripAnsiCodes("array[0] and a[b"),
            "a literal '[' in model output is content, not a control sequence",
        )
    }
}
