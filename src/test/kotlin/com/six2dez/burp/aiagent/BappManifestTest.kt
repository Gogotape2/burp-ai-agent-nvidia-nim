package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 29 / BUILD-02 (D-04) — pins BappManifest.bmf, the build contract PortSwigger runs.
 *
 * PortSwigger forks the repo, runs `BuildCommand` and publishes the file at `EntryPoint`. Both values
 * are compared byte-for-byte (case-sensitive): a manifest that names another task, or a path that
 * differs in one character from what bappJar writes, would publish the wrong JAR or none. The test
 * also pins the build side of the contract: the store file name occurs exactly once in
 * build.gradle.kts, so no second task can write a file under it.
 *
 * Both files are read from disk; `tasks.test` declares them as inputs (`bappManifest`, and
 * build.gradle.kts is part of every build's configuration).
 */
class BappManifestTest {
    private fun readProjectFile(relativePath: String): String {
        val file = File(relativePath)
        assertTrue(
            file.isFile,
            "Expected `$relativePath` relative to `${System.getProperty("user.dir")}`, resolved as `${file.absolutePath}`.",
        )
        return file.readText()
    }

    private fun manifest(): Map<String, String> {
        val text = readProjectFile("BappManifest.bmf")
        val entries = linkedMapOf<String, String>()
        text.lines().filter { it.isNotEmpty() }.forEach { line ->
            val separator = line.indexOf(": ")
            assertTrue(separator > 0, "every manifest line must be `Key: value`, got `$line`")
            val key = line.substring(0, separator)
            assertFalse(key in entries, "duplicate manifest key `$key`")
            entries[key] = line.substring(separator + 2)
        }
        return entries
    }

    @Test
    fun buildCommandAndEntryPointAreTheStoreContract() {
        val entries = manifest()
        assertEquals("./gradlew bappJar", entries["BuildCommand"])
        assertEquals("build/libs/custom-ai-agent-bapp.jar", entries["EntryPoint"])
    }

    @Test
    fun entryPointFileNameIsTheOnlyArchiveNameBappJarWrites() {
        val entryPoint = manifest().getValue("EntryPoint")
        val fileName = entryPoint.substringAfterLast('/')
        val buildScript = readProjectFile("build.gradle.kts")

        val archiveFileName = Regex("""archiveFileName\.set\("([^"]+)"\)""").findAll(buildScript).map { it.groupValues[1] }.toList()
        assertEquals(listOf(fileName), archiveFileName, "bappJar must be the only task with a fixed archive file name")
        assertEquals(1, Regex(Regex.escape(fileName.removeSuffix(".jar"))).findAll(buildScript).count())
    }

    @Test
    fun screenVersionMatchesTheGradleVersion() {
        val buildScript = readProjectFile("build.gradle.kts")
        val version = Regex("""(?m)^version = "([^"]+)"""").find(buildScript)?.groupValues?.get(1)
        assertEquals(version, manifest()["ScreenVersion"])
    }

    @Test
    fun manifestIsAsciiWithLfLineEndings() {
        val bytes = File("BappManifest.bmf").readBytes()
        assertTrue(bytes.isNotEmpty(), "BappManifest.bmf is empty")
        assertTrue(bytes.all { it.toInt() in 0x20..0x7E || it.toInt() == 0x0A }, "manifest must be printable ASCII with LF line endings")
        assertEquals(0x0A, bytes.last().toInt(), "manifest must end with a newline")
        val names = manifest().keys
        assertTrue(names.containsAll(listOf("Name", "ScreenVersion", "EntryPoint", "BuildCommand")), "keys: $names")
        assertEquals("Custom AI Agent", manifest()["Name"])
    }
}
