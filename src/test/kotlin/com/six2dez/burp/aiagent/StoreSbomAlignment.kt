package com.six2dez.burp.aiagent

/**
 * Phase 30 / CI-02 (review finding CR-01): the rules that decide whether the SBOM source classpath resolves
 * every module the BApp Store JAR packages at the version that JAR packages.
 *
 * The release publishes one `bom.json` for both JARs, generated from the full build's runtime classpath. That
 * is only true for the store JAR if the full classpath resolves each store module to the same version. Gradle
 * resolves version conflicts separately for each configuration, so this does not follow from `extendsFrom`:
 * CR-01 found `io.ktor:ktor-websocket-serialization` at 3.0.2 in the store JAR and 3.1.3 in the SBOM.
 *
 * The functions are pure over `group:module:version` lists, so `StoreSbomAlignmentTest` proves every rule red
 * and green on synthetic lists in plain `test`, and StoreJarContentTest applies them to the real resolved
 * classpaths in the `storeJarContentTest` Gradle task. Fix a reported module with a version constraint in
 * build.gradle.kts; never by narrowing the check.
 */
internal object StoreSbomAlignment {
    /** System property carrying the store runtime classpath (what bappJar packages) as `group:module:version` entries. */
    const val STORE_MODULES_PROPERTY = "burp.aiagent.storeModules"

    /** System property carrying the classpath bom.json is generated from, in the same form. */
    const val SBOM_MODULES_PROPERTY = "burp.aiagent.sbomModules"

    /** System property carrying the name of the configuration bom.json is generated from. */
    const val SBOM_CONFIGURATION_PROPERTY = "burp.aiagent.sbomConfiguration"

    enum class Kind {
        DIFFERENT_VERSION,
        MISSING_FROM_SBOM_SOURCE,
    }

    data class Misalignment(
        val module: String,
        val storeVersion: String,
        val sbomVersion: String?,
        val kind: Kind,
    )

    /**
     * Parses comma-joined `group:module:version` entries into a map from `group:module` to version, sorted by
     * key. Blank pieces are skipped, so a blank string gives an empty map. A malformed entry, or a module listed
     * twice with different versions, throws [IllegalArgumentException] naming it; a repeated identical entry
     * counts once.
     */
    fun parse(joined: String): Map<String, String> {
        val modules = sortedMapOf<String, String>()
        joined
            .split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { entry ->
                val parts = entry.split(':')
                require(parts.size == COORDINATE_PARTS && parts.all { it.isNotBlank() }) {
                    "Malformed module entry '$entry': expected group:module:version"
                }
                val module = "${parts[0]}:${parts[1]}"
                val version = parts[2]
                val previous = modules.putIfAbsent(module, version)
                require(previous == null || previous == version) {
                    "Module $module is listed twice with different versions: $previous and $version"
                }
            }
        return modules
    }

    /**
     * Every [store] module whose version in [sbom] differs, or that [sbom] lacks, sorted by module. A module only
     * [sbom] holds (a full-only library) is never reported: the SBOM source is allowed to be a superset.
     */
    fun misalignments(
        store: Map<String, String>,
        sbom: Map<String, String>,
    ): List<Misalignment> =
        store
            .mapNotNull { (module, storeVersion) ->
                val sbomVersion = sbom[module]
                when {
                    sbomVersion == null -> Misalignment(module, storeVersion, null, Kind.MISSING_FROM_SBOM_SOURCE)
                    sbomVersion != storeVersion -> Misalignment(module, storeVersion, sbomVersion, Kind.DIFFERENT_VERSION)
                    else -> null
                }
            }.sortedBy { it.module }

    /** The failure message: what went wrong, how to fix it, then one line per misaligned module. */
    fun report(
        configuration: String,
        misalignments: List<Misalignment>,
    ): String =
        "bom.json is generated from $configuration, which does not resolve every module the BApp Store JAR " +
            "packages (runtimeClasspath) to the store JAR's version (CR-01).\n" +
            "Fix it with a version constraint in build.gradle.kts; never with a narrower check.\n" +
            misalignments.joinToString("\n") { line(configuration, it) }

    private fun line(
        configuration: String,
        misalignment: Misalignment,
    ): String =
        when (misalignment.sbomVersion) {
            null -> "  ${misalignment.module}: store JAR ${misalignment.storeVersion}, absent from $configuration"
            else -> "  ${misalignment.module}: store JAR ${misalignment.storeVersion}, $configuration ${misalignment.sbomVersion}"
        }

    private const val COORDINATE_PARTS = 3
}
