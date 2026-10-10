package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 29 / BUILD-02, BUILD-03 (D-04 amended) — pins the README's build instructions and its warning
 * against loading both builds at once.
 *
 * Both flavors register under the same Burp extension name, so nothing in Burp tells them apart. The
 * README is the one place a user learns that loading both gives two tabs, two MCP servers on one port
 * and two writers of the shared ~/.burp-ai-agent directory. The retired build command must not come
 * back: it now fails with a retirement message.
 *
 * README.md is read from disk; `tasks.test` declares it as an input (`readmeClaims`).
 */
class ReadmeFlavorWarningTest {
    private fun readme(): String {
        val file = File("README.md")
        assertTrue(file.isFile, "README.md not found from ${System.getProperty("user.dir")}")
        return file.readText()
    }

    @Test
    fun readmeNamesBothFlavorTasksAndTheStoreJar() {
        val text = readme()
        assertTrue(text.contains("./gradlew clean fullJar"), "README must show the full build command")
        assertTrue(text.contains("./gradlew clean bappJar"), "README must show the BApp Store build command")
        assertTrue(text.contains("build/libs/custom-ai-agent-bapp.jar"), "README must name the store JAR path")
        assertTrue(text.contains("build/libs/Custom-AI-Agent-full-<version>.jar"), "README must name the full JAR path")
    }

    @Test
    fun readmeNoLongerNamesTheRetiredTask() {
        val text = readme()
        assertFalse(text.contains("gradlew clean shadowJar"), "README still names the retired shadowJar build")
        assertFalse(text.contains("-PstoreBuild"), "README still names the retired storeBuild Gradle property")
    }

    @Test
    fun readmeWarnsAgainstLoadingBothBuilds() {
        val text = readme()
        val start = text.indexOf("**Load only one build.**")
        assertTrue(start >= 0, "README must carry the 'Load only one build' warning")
        val end = text.indexOf("\n\n", start).let { if (it < 0) text.length else it }
        val paragraph = text.substring(start, end)
        listOf("Custom AI Agent", "MCP", "port", ".burp-ai-agent", "Extensions list").forEach { term ->
            assertTrue(paragraph.contains(term), "the warning paragraph must mention `$term`: $paragraph")
        }

        val loadSection = text.indexOf("### 2. Load into Burp")
        val nextSection = text.indexOf("### 3.", loadSection)
        assertTrue(loadSection in 0 until start && start < nextSection, "the warning must sit under '2. Load into Burp'")
    }
}
