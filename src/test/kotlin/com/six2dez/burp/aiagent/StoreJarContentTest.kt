package com.six2dez.burp.aiagent

import com.six2dez.burp.aiagent.StoreJarInspector.FACTORY_SERVICES_ENTRY
import com.six2dez.burp.aiagent.StoreJarInspector.Rule
import com.six2dez.burp.aiagent.StoreJarInspector.Violation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.fail

/**
 * Phase 30 / CI-01 (ROADMAP SC2): the real BApp Store JAR holds no full-only or CLI content.
 *
 * Runs ONLY in the `storeJarContentTest` Gradle task (plain `test` excludes it): that task builds the store
 * JAR first and passes its path and the src/full class directories as the system properties
 * [StoreJarInspector.STORE_JAR_PROPERTY] and [StoreJarInspector.FULL_CLASS_DIRS_PROPERTY]. A missing property
 * FAILS rather than skips, because a skipped content check passes vacuously.
 *
 * Next to the real-JAR check, a planted copy of the same JAR proves the rules fire against the real
 * artifact's structure, and a non-vacuity check proves both inputs are real build outputs.
 */
class StoreJarContentTest {
    @Test
    fun realStoreJarHoldsNoFullOnlyOrCliEntry() {
        val jar = storeJar()
        val violations = StoreJarInspector.inspect(jar, fullOnly())
        assertTrue(violations.isEmpty(), StoreJarInspector.report(jar, violations))
    }

    @Test
    fun plantedCopyOfTheRealJarIsReportedNamingEachPlantedEntry(
        @TempDir dir: File,
    ) {
        val real = storeJar()
        val fullOnly = fullOnly()
        val shaBefore = sha256(real)
        val planted = plantedCopy(real, File(dir, "planted.jar"))

        // Relative to the real JAR's own result, so a packaging drift fails the real-JAR test alone.
        val expected = (StoreJarInspector.inspect(real, fullOnly) + PLANTED_VIOLATIONS).distinct().sortedBy { it.entry }
        val actual = StoreJarInspector.inspect(planted, fullOnly)
        assertEquals(expected, actual, "the planted copy must be reported naming exactly the planted entries")
        assertEquals(shaBefore, sha256(real), "the inspection must never modify the real store JAR")
    }

    @Test
    fun inspectionReadsARealJarAndARealFullOutput() {
        val jar = storeJar()
        val names = StoreJarInspector.entryNames(jar)
        assertTrue(names.size > MIN_JAR_ENTRIES, "${jar.absolutePath} has only ${names.size} entries; expected more than $MIN_JAR_ENTRIES")
        assertTrue(EXTENSION_CLASS in names, "${jar.absolutePath} does not contain $EXTENSION_CLASS")
        assertTrue(FACTORY_SERVICES_ENTRY in names, "${jar.absolutePath} does not contain $FACTORY_SERVICES_ENTRY")

        val fullOnly = fullOnly()
        assertTrue(
            fullOnly.size >= MIN_FULL_ENTRIES,
            "the derived src/full set has only ${fullOnly.size} entries; expected at least $MIN_FULL_ENTRIES",
        )
        // A backslash-separated walk (Windows) would hold neither, and layer A would pass vacuously.
        assertTrue(FULL_PROFILE_CLASS in fullOnly, "the derived src/full set does not contain $FULL_PROFILE_CLASS")
        assertTrue(PLANTED_CLASS in fullOnly, "the derived src/full set does not contain $PLANTED_CLASS")
    }

    private fun requiredProperty(name: String): String =
        System.getProperty(name)?.takeIf { it.isNotBlank() }
            ?: fail("System property $name is not set. This class runs only in the storeJarContentTest task: $RUN_COMMAND")

    private fun storeJar(): File {
        val jar = File(requiredProperty(StoreJarInspector.STORE_JAR_PROPERTY))
        if (!jar.isFile) fail("The store JAR ${jar.absolutePath} does not exist. Run: $RUN_COMMAND")
        return jar
    }

    private fun fullOnly(): Set<String> {
        val dirs =
            requiredProperty(StoreJarInspector.FULL_CLASS_DIRS_PROPERTY)
                .split(File.pathSeparator)
                .filter { it.isNotBlank() }
                .map(::File)
        return StoreJarInspector.fullOnlyEntries(dirs)
    }

    /** Copies [real] entry by entry into [out], plants a CLI backend class and appends a CLI factory line. */
    private fun plantedCopy(
        real: File,
        out: File,
    ): File {
        ZipFile(real).use { source ->
            ZipOutputStream(out.outputStream().buffered()).use { zip ->
                // The planted class is skipped if the source has it, so the copy never writes a duplicate name.
                source
                    .entries()
                    .asSequence()
                    .filter { it.name != PLANTED_CLASS }
                    .forEach { copyEntry(source, it, zip) }
                zip.putNextEntry(ZipEntry(PLANTED_CLASS))
                zip.write(byteArrayOf(0xCA.toByte(), 0xFE.toByte()))
                zip.closeEntry()
            }
        }
        return out
    }

    /** Copies one entry; the AiBackendFactory services file gets the planted CLI factory line appended. */
    private fun copyEntry(
        source: ZipFile,
        entry: ZipEntry,
        zip: ZipOutputStream,
    ) {
        zip.putNextEntry(ZipEntry(entry.name))
        if (entry.name == FACTORY_SERVICES_ENTRY) {
            val text = source.getInputStream(entry).use { it.readBytes().toString(Charsets.UTF_8) }
            zip.write("$text\n$PLANTED_FACTORY".toByteArray(Charsets.UTF_8))
        } else if (!entry.isDirectory) {
            source.getInputStream(entry).use { it.copyTo(zip) }
        }
        zip.closeEntry()
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        DigestInputStream(file.inputStream().buffered(), digest).use { it.copyTo(OutputStream.nullOutputStream()) }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val RUN_COMMAND = "./gradlew bappJar storeJarContentTest"
        const val MIN_JAR_ENTRIES = 1_000
        const val MIN_FULL_ENTRIES = 100
        const val EXTENSION_CLASS = "com/six2dez/burp/aiagent/BurpAiAgentExtension.class"
        const val FULL_PROFILE_CLASS = "com/six2dez/burp/aiagent/full/FullFlavorProfile.class"
        const val PLANTED_CLASS = "com/six2dez/burp/aiagent/backends/cli/CliBackend.class"
        const val PLANTED_FACTORY = "com.six2dez.burp.aiagent.backends.cli.ClaudeCliBackendFactory"

        val PLANTED_VIOLATIONS =
            listOf(
                Violation(PLANTED_CLASS, Rule.DERIVED_FULL_CLASS),
                Violation("$FACTORY_SERVICES_ENTRY: $PLANTED_FACTORY", Rule.FACTORY_LIST),
            )
    }
}
