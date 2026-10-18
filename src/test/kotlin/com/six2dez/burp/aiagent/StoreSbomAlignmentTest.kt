package com.six2dez.burp.aiagent

import com.six2dez.burp.aiagent.StoreSbomAlignment.Kind
import com.six2dez.burp.aiagent.StoreSbomAlignment.Misalignment
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 30 / CI-02 (review finding CR-01): fail-first proof of every [StoreSbomAlignment] rule, on synthetic
 * module lists.
 *
 * StoreJarContentTest applies the rules to the real resolved classpaths in the `storeJarContentTest` task,
 * which are aligned, so a comparator that stopped reporting would leave it green over an SBOM that named the
 * wrong version again. This class proves each rule red and green in plain `test`, which pr-gate runs on all
 * three operating systems: aligned lists, the CR-01 version difference, a module the SBOM source lacks, the
 * allowed full-only superset, sorted and repeatable output, the parser's rejections and the report lines.
 */
class StoreSbomAlignmentTest {
    @Test
    fun alignedClasspathsReportNothing() {
        val store = mapOf(SERVER_CORE to "3.1.3", SERIALIZATION to "3.1.3", SERIALIZATION_JVM to "3.1.3")
        val sbom = store + mapOf(CLIENT_CORE to "3.1.3", CLIENT_CIO to "3.1.3")
        assertEquals(
            emptyList<Misalignment>(),
            StoreSbomAlignment.misalignments(store, sbom),
            "every store module has the same version in the SBOM source, so nothing may be reported",
        )
    }

    @Test
    fun aVersionDifferenceIsReportedNamingTheModuleAndBothVersions() {
        val store = mapOf(SERIALIZATION_JVM to "3.0.2", SERVER_CORE to "3.1.3", SERIALIZATION to "3.0.2")
        val sbom = mapOf(SERIALIZATION to "3.1.3", SERIALIZATION_JVM to "3.1.3", SERVER_CORE to "3.1.3")
        assertEquals(
            listOf(
                Misalignment(SERIALIZATION, "3.0.2", "3.1.3", Kind.DIFFERENT_VERSION),
                Misalignment(SERIALIZATION_JVM, "3.0.2", "3.1.3", Kind.DIFFERENT_VERSION),
            ),
            StoreSbomAlignment.misalignments(store, sbom),
            "the CR-01 fixture must report $SERIALIZATION and $SERIALIZATION_JVM at store 3.0.2 against SBOM 3.1.3, " +
                "and never the aligned $SERVER_CORE",
        )
    }

    @Test
    fun aStoreModuleTheSbomSourceLacksIsReportedAsMissing() {
        val store = mapOf(SERVER_CORE to "3.1.3", NETTY to "3.1.3")
        val sbom = mapOf(SERVER_CORE to "3.1.3")
        assertEquals(
            listOf(Misalignment(NETTY, "3.1.3", null, Kind.MISSING_FROM_SBOM_SOURCE)),
            StoreSbomAlignment.misalignments(store, sbom),
            "$NETTY 3.1.3 is in the store classpath but not in the SBOM source; it must be reported, never dropped",
        )
    }

    @Test
    fun aModuleOnlyTheSbomSourceHoldsIsNeverReported() {
        val store = mapOf(SERVER_CORE to "3.1.3")
        val sbom = mapOf(SERVER_CORE to "3.1.3", CLIENT_CIO to "3.1.3")
        assertEquals(
            emptyList<Misalignment>(),
            StoreSbomAlignment.misalignments(store, sbom),
            "the full-only $CLIENT_CIO is allowed in the SBOM source (a superset) and must never be reported",
        )
    }

    @Test
    fun misalignmentsAreSortedAndRepeatable() {
        val ordered = listOf(SERIALIZATION to "3.0.2", SERIALIZATION_JVM to "3.0.2", NETTY to "3.0.1", SERVER_CORE to "3.0.0")
        val sbom = mapOf(SERIALIZATION to "3.1.3", SERIALIZATION_JVM to "3.1.3", NETTY to "3.1.3", SERVER_CORE to "3.1.3")
        val shuffled = listOf(ordered[2], ordered[0], ordered[3], ordered[1])

        val fromOrdered = StoreSbomAlignment.misalignments(linkedMapOf(*ordered.toTypedArray()), sbom)
        val fromReversed = StoreSbomAlignment.misalignments(linkedMapOf(*ordered.reversed().toTypedArray()), sbom)
        val fromShuffled = StoreSbomAlignment.misalignments(linkedMapOf(*shuffled.toTypedArray()), sbom)

        assertEquals(listOf(SERVER_CORE, NETTY, SERIALIZATION, SERIALIZATION_JVM), fromOrdered.map { it.module }, "sorted by module")
        assertEquals(fromOrdered, fromReversed, "the input order (reversed) must not change the result")
        assertEquals(fromOrdered, fromShuffled, "the input order (shuffled) must not change the result")
        assertEquals(
            StoreSbomAlignment.report(CONFIGURATION, fromOrdered),
            StoreSbomAlignment.report(CONFIGURATION, fromShuffled),
            "the same misalignments must give the same report text",
        )
        val again = StoreSbomAlignment.misalignments(linkedMapOf(*ordered.toTypedArray()), sbom)
        assertEquals(fromOrdered, again, "two calls over unchanged inputs must give the same list")
        assertEquals(
            StoreSbomAlignment.report(CONFIGURATION, fromOrdered),
            StoreSbomAlignment.report(CONFIGURATION, again),
            "two calls over unchanged inputs must give the same report text",
        )
    }

    @Test
    fun parseRejectsMalformedOrConflictingEntries() {
        listOf("g:a", "g::1").forEach { entry ->
            val error = assertThrows(IllegalArgumentException::class.java, { StoreSbomAlignment.parse(entry) }, "'$entry' must be rejected")
            assertTrue(entry in error.message.orEmpty(), "the error for '$entry' must name it: ${error.message}")
        }
        val conflict = assertThrows(IllegalArgumentException::class.java, { StoreSbomAlignment.parse("g:a:1,g:a:2") }, "conflict")
        assertTrue("g:a" in conflict.message.orEmpty(), "the conflict error must name g:a: ${conflict.message}")

        assertEquals(mapOf("g:a" to "1"), StoreSbomAlignment.parse("g:a:1,g:a:1"), "a repeated identical entry counts once")
        assertEquals(emptyMap<String, String>(), StoreSbomAlignment.parse(""), "a blank string parses to no modules")
        assertEquals(emptyMap<String, String>(), StoreSbomAlignment.parse(",,,"), "a string of commas parses to no modules")
        assertEquals(
            mapOf(SERIALIZATION to "3.0.2", SERVER_CORE to "3.1.3"),
            StoreSbomAlignment.parse(" $SERVER_CORE:3.1.3 ,$SERIALIZATION:3.0.2"),
            "pieces are trimmed and keyed by group:module",
        )
        // An empty store list reports nothing: this is why the real check has a non-vacuity floor.
        assertEquals(
            emptyList<Misalignment>(),
            StoreSbomAlignment.misalignments(emptyMap(), mapOf(SERVER_CORE to "3.1.3")),
            "an empty store list has nothing to compare",
        )
    }

    @Test
    fun reportNamesEveryModuleWithBothVersionsAndTheConfiguration() {
        val report =
            StoreSbomAlignment.report(
                CONFIGURATION,
                listOf(
                    Misalignment(SERIALIZATION, "3.0.2", "3.1.3", Kind.DIFFERENT_VERSION),
                    Misalignment(NETTY, "3.1.3", null, Kind.MISSING_FROM_SBOM_SOURCE),
                ),
            )
        val lines = report.lines()
        assertTrue(
            "  $SERIALIZATION: store JAR 3.0.2, $CONFIGURATION 3.1.3" in lines,
            "the report must name $SERIALIZATION with both versions and the configuration:\n$report",
        )
        assertTrue(
            "  $NETTY: store JAR 3.1.3, absent from $CONFIGURATION" in lines,
            "the report must name the missing $NETTY and the configuration:\n$report",
        )
        assertTrue(CONFIGURATION in lines.first(), "the header must name the configuration bom.json is generated from:\n$report")
    }

    private companion object {
        const val CONFIGURATION = "fullRuntimeClasspath"
        const val SERIALIZATION = "io.ktor:ktor-websocket-serialization"
        const val SERIALIZATION_JVM = "io.ktor:ktor-websocket-serialization-jvm"
        const val SERVER_CORE = "io.ktor:ktor-server-core"
        const val NETTY = "io.ktor:ktor-server-netty"
        const val CLIENT_CORE = "io.ktor:ktor-client-core"
        const val CLIENT_CIO = "io.ktor:ktor-client-cio"
    }
}
