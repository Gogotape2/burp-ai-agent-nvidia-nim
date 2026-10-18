package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 30 (CI-02, ROADMAP SC3, decisions D-01..D-04): every tagged release gates on the same store-JAR
 * inspection PRs run, then publishes both JARs, each with a `.sha256` that names the published file.
 *
 * - D-01: the store JAR is published as `Custom-AI-Agent-bapp-<version>.jar`, a copy of the Gradle output
 *   that `cmp` proves byte-for-byte equal. The Gradle output name stays the one BappManifest.bmf pins.
 * - D-02: lint, both flavors' suites and `bappJar fullJar storeJarContentTest` run before anything is
 *   staged or published, so a tag on a commit that never ran PR CI cannot publish an unchecked store JAR.
 * - D-03: checksums are computed inside the staging directory after the rename, in `sha256sum` format.
 * - D-04: the notes open with a fixed "Which JAR?" block the workflow writes, carrying README's
 *   "Load only one build." warning verbatim and making no isolation, identity or origin claim.
 * - SBOM (CR-01): bom.json is generated after the gate whose storeJarContentTest checks that its source
 *   classpath resolves every BApp Store dependency at the store JAR's version, and the block says what it
 *   covers.
 *
 * Why a text guard: the release workflow only runs on a tag push, and there is no local runner for it.
 * A reordered step, a dropped glob or a `continue-on-error` would leave every local gate green until the
 * next release published the wrong thing. `.github/workflows` is the declared `workflowsStructuralInputs`
 * input of `test` and README.md its `readmeClaims` input, so an edit to either re-runs this guard.
 *
 * BOUND: plain text, no YAML parser (none is on the test classpath). A comment is a line whose trimmed
 * text starts with `#`, which also hides Markdown headings inside a `run:` block from the marker scans;
 * a step is the lines from its `- name:` line to the next step at the same indentation. A step that is
 * present but skipped some other way is invisible to it; review owns that.
 */
class ReleaseWorkflowGuardTest {
    @Test
    fun releaseRunsTheSameGateBeforeStagingAndPublishing() {
        val messages = orderViolations(RELEASE_WORKFLOW, releaseLines())
        assertTrue(
            messages.isEmpty(),
            "$RELEASE_WORKFLOW no longer gates and stages in order (lint, suites, inspection, SBOM, staging, " +
                "checksums, publish; D-02):\n" + messages.joinToString("\n"),
        )
    }

    @Test
    fun storeAssetIsAVersionedCopyCheckedByteForByte() {
        val staging = live(stepBlock(releaseLines(), STAGING_STEP))
        val messages = mutableListOf<String>()
        if (staging.none { it.contains(BAPP_ASSET_LINE) }) {
            messages += "the staging step no longer names the versioned store asset `$BAPP_ASSET_LINE` (D-01)"
        }
        if (staging.none { it.trim().startsWith("cmp ") }) {
            messages += "the staging step no longer proves the staged store copy byte-for-byte with `cmp` (D-01)"
        }
        if (staging.none { it.contains("rm -rf build/release") }) {
            messages += "the staging step no longer empties build/release first (a stale JAR could be published)"
        }
        if (staging.none { it.contains("::error::") }) {
            messages += "the staging step no longer fails with an ::error:: line on a missing JAR or a tag mismatch"
        }
        assertTrue(messages.isEmpty(), "$RELEASE_WORKFLOW / $STAGING_STEP:\n" + messages.joinToString("\n"))
    }

    @Test
    fun publishListsEveryAssetAndFailsOnAMissingOne() {
        val publish = live(publishBlock(releaseLines()))
        assertEquals(
            PUBLISHED_FILES,
            filesList(publish),
            "$RELEASE_WORKFLOW: the publish step must list exactly one glob per asset kind, so a missing " +
                "store asset cannot pass on the full asset's match",
        )
        assertTrue(
            publish.any { it.trim() == "fail_on_unmatched_files: true" },
            "$RELEASE_WORKFLOW: the publish step no longer sets `fail_on_unmatched_files: true` (the action " +
                "defaults to false and would publish a partial release)",
        )
    }

    @Test
    fun nothingCanPublishAfterAFailedStep() {
        val lines = releaseLines()
        val tolerated = live(lines).filter { it.contains("continue-on-error") }
        assertTrue(
            tolerated.isEmpty(),
            "$RELEASE_WORKFLOW: a step tolerates failure, so a red gate could still reach the publish step:\n" +
                tolerated.joinToString("\n") { "  ${it.trim()}" },
        )
        val conditions = live(publishBlock(lines)).filter { it.trim().startsWith("if:") }
        assertTrue(
            conditions.isEmpty(),
            "$RELEASE_WORKFLOW: the publish step carries an `if:` (e.g. always()) that could run it after a " +
                "failed gate: ${conditions.map { it.trim() }}",
        )
    }

    @Test
    fun theTagIsReadFromTheEnvironment() {
        val lines = releaseLines()
        assertTrue(
            live(stepBlock(lines, STAGING_STEP)).any { it.contains("GITHUB_REF") },
            "$RELEASE_WORKFLOW / $STAGING_STEP: the tag is no longer read from GITHUB_REF in the environment",
        )
        val interpolated = live(lines).filter { TAG_EXPRESSION.containsMatchIn(it) }
        assertTrue(
            interpolated.isEmpty(),
            "$RELEASE_WORKFLOW: the tag is interpolated through a workflow expression, which a crafted tag " +
                "name can turn into script injection; read GITHUB_REF from the environment instead:\n" +
                interpolated.joinToString("\n") { "  ${it.trim()}" },
        )
    }

    @Test
    fun whichJarBlockMirrorsTheReadmeWarning() {
        val region = whichJarRegion(releaseLines())
        val warning = readmeWarning()
        val messages = mutableListOf<String>()
        if (warning !in region) {
            messages += "the block no longer carries README's warning verbatim: `$warning`"
        }
        REQUIRED_IN_BLOCK.filter { term -> region.none { it.contains(term) } }.forEach {
            messages += "the block no longer mentions `$it`"
        }
        assertTrue(
            messages.isEmpty(),
            "$RELEASE_WORKFLOW: the Which JAR? release-notes block (D-04) drifted:\n" + messages.joinToString("\n"),
        )
    }

    @Test
    fun whichJarBlockMakesNoIsolationIdentityOrOriginClaim() {
        // README's warning is carried verbatim and says the two builds "look identical" in Burp's
        // Extensions list, which is about how they appear, not about their bytes. Its wording is pinned by
        // ReadmeFlavorWarningTest, so it is the one line exempt from this scan.
        val warning = readmeWarning()
        val hits =
            whichJarRegion(releaseLines())
                .filter { it != warning }
                .flatMap { line -> FORBIDDEN_IN_BLOCK.filter { line.lowercase().contains(it) }.map { it to line } }
        assertTrue(
            hits.isEmpty(),
            "$RELEASE_WORKFLOW: the Which JAR? block overclaims. The BApp Store asset is the store flavor and " +
                "build command, not the file the BApp Store distributes; the store build may still load code " +
                "from outside its JAR until Phase 31 (ADR-18 residual); a checksum on the same release only " +
                "shows a download is complete:\n" + hits.joinToString("\n") { "  `${it.first}` in: ${it.second}" },
        )
    }

    @Test
    fun releaseNotesOpenWithTheWhichJarBlock() {
        val lines = releaseLines()
        val messages = heredocQuotingMessages(lines) + notesWriteMessages(stepBlock(lines, NOTES_STEP)) + notesPositionMessages(lines)
        assertTrue(messages.isEmpty(), "$RELEASE_WORKFLOW / $NOTES_STEP:\n" + messages.joinToString("\n"))
    }

    /** The block must come from exactly one quoted heredoc; an unquoted one runs the Markdown backticks. */
    private fun heredocQuotingMessages(lines: List<String>): List<String> {
        val starts = lines.filter { it.contains("<<") && it.contains(HEREDOC_MARKER) }
        if (starts.size == 1 && starts.single().contains("<<'$HEREDOC_MARKER'")) return emptyList()
        return listOf(
            "the block must be written by exactly one quoted heredoc `<<'$HEREDOC_MARKER'` (an unquoted " +
                "one runs the Markdown backticks as commands): $starts",
        )
    }

    /** The notes file is written with `>` from the block, then the CHANGELOG section is appended with `>>`. */
    private fun notesWriteMessages(notes: List<String>): List<String> {
        val messages = mutableListOf<String>()
        val write = notes.indexOfFirst { !isComment(it) && it.contains("> $NOTES_FILE") && !it.contains(">> $NOTES_FILE") }
        val append = notes.indexOfFirst { !isComment(it) && it.contains(">> $NOTES_FILE") }
        if (write < 0 || append < 0 || write >= append) {
            messages += "the step must write $NOTES_FILE with `>` from the block before it appends the CHANGELOG " +
                "section with `>>` (write at ${write + 1}, append at ${append + 1} of the step)"
        } else if (!notes[write].contains("which-jar.md")) {
            messages += "the first write of $NOTES_FILE no longer comes from the block: ${notes[write].trim()}"
        }
        if (live(notes).none { it.contains("notes_file=$NOTES_FILE") && it.contains("GITHUB_OUTPUT") }) {
            messages += "the step no longer writes `notes_file=$NOTES_FILE` to GITHUB_OUTPUT"
        }
        return messages
    }

    /** The notes step sits after the checksum step and before the publish step. */
    private fun notesPositionMessages(lines: List<String>): List<String> {
        val notesAt = lines.indexOfFirst { it.trim() == "- name: $NOTES_STEP" }
        val checksumAt = lines.indexOfFirst { it.trim() == "- name: $CHECKSUM_STEP" }
        val publishAt = lines.indexOfFirst { !isComment(it) && it.contains(PUBLISH_ACTION) }
        if (checksumAt >= 0 && publishAt >= 0 && notesAt in (checksumAt + 1) until publishAt) return emptyList()
        return listOf(
            "the notes step must sit after `$CHECKSUM_STEP` and before the publish step " +
                "(lines ${checksumAt + 1}, ${notesAt + 1}, ${publishAt + 1})",
        )
    }

    @Test
    fun aStepOutOfOrderIsReported() {
        // Fail-first proof: if the order check stopped reporting, the whole-file check above would pass
        // over a workflow that checksums before the rename (the .sha256 would name the wrong file).
        val swapped = syntheticRelease(checksumBeforeStaging = true)
        val messages = orderViolations("synthetic.yml", swapped)
        assertEquals(1, messages.size, "expected exactly one out-of-order message, got $messages")
        val message = messages.single()
        assertTrue(
            message.contains(BAPP_ASSET_LINE) && message.contains("sha256sum \"\$f\""),
            "the message must name both out-of-order lines: $message",
        )
        assertEquals(
            emptyList<String>(),
            orderViolations("synthetic.yml", syntheticRelease(checksumBeforeStaging = false)),
            "a correctly ordered release must not be reported",
        )
    }

    private data class Marker(
        val what: String,
        val matches: (String) -> Boolean,
    )

    private fun releaseLines(): List<String> = projectFile(RELEASE_WORKFLOW).readLines()

    private fun projectFile(relative: String): File {
        val file = File(SourceRoots.layout().projectDir, relative)
        assertTrue(file.isFile, "expected $relative at ${file.absolutePath}")
        return file
    }

    private fun isComment(line: String): Boolean = line.trim().startsWith("#")

    private fun live(lines: List<String>): List<String> = lines.filterNot { isComment(it) }

    private fun tokens(line: String): Set<String> = line.split(TOKEN_SEPARATORS).filter { it.isNotEmpty() }.toSet()

    private fun gradleRuns(vararg required: String): (String) -> Boolean = { line -> line.contains("./gradlew") && tokens(line).containsAll(required.toList()) }

    /**
     * One message per adjacent pair of [order] markers whose first matching non-comment lines are not
     * strictly increasing, naming both lines; one message per marker no line matches.
     */
    private fun orderViolations(
        fileName: String,
        lines: List<String>,
    ): List<String> {
        val found =
            order.map { marker ->
                marker to lines.indexOfFirst { !isComment(it) && marker.matches(it) }
            }
        val missing = found.filter { it.second < 0 }.map { "$fileName: no line ${it.first.what}" }
        if (missing.isNotEmpty()) return missing
        return found.zipWithNext().filter { (a, b) -> a.second >= b.second }.map { (a, b) ->
            "$fileName:${a.second + 1} `${lines[a.second].trim()}` (${a.first.what}) must come before " +
                "$fileName:${b.second + 1} `${lines[b.second].trim()}` (${b.first.what})"
        }
    }

    /** Trimmed lines between the `<<'WHICH_JAR'` line and its terminator; fails if the block is missing. */
    private fun whichJarRegion(lines: List<String>): List<String> {
        val start = lines.indexOfFirst { it.contains("<<'$HEREDOC_MARKER'") }
        assertTrue(start >= 0, "$RELEASE_WORKFLOW no longer writes the Which JAR? block with <<'$HEREDOC_MARKER'")
        val rest = lines.drop(start + 1)
        val end = rest.indexOfFirst { it.trim() == HEREDOC_MARKER }
        assertTrue(end >= 0, "$RELEASE_WORKFLOW: the <<'$HEREDOC_MARKER' heredoc has no terminator line")
        val region = rest.take(end).map { it.trim() }
        assertTrue(region.count { it.isNotEmpty() } >= MIN_BLOCK_LINES, "the Which JAR? block is nearly empty: $region")
        return region
    }

    /** README's "Load only one build." line, trimmed (README.md is the declared `readmeClaims` input). */
    private fun readmeWarning(): String {
        val line = projectFile(README).readLines().map { it.trim() }.firstOrNull { it.startsWith(README_WARNING) }
        assertTrue(line != null, "$README no longer has a line starting with $README_WARNING")
        return line!!
    }

    /** Lines of the step whose `- name:` is [name], up to the next step at the same indentation. */
    private fun stepBlock(
        lines: List<String>,
        name: String,
    ): List<String> {
        val start = lines.indexOfFirst { it.trim() == "- name: $name" }
        assertTrue(start >= 0, "$RELEASE_WORKFLOW has no step named `$name`")
        return blockFrom(lines, start)
    }

    /** The step that uses softprops/action-gh-release: from its `- ` line to the next step. */
    private fun publishBlock(lines: List<String>): List<String> {
        val uses = lines.indexOfFirst { !isComment(it) && it.contains(PUBLISH_ACTION) }
        assertTrue(uses >= 0, "$RELEASE_WORKFLOW no longer uses $PUBLISH_ACTION")
        val start = (uses downTo 0).first { lines[it].trim().startsWith("- ") }
        return blockFrom(lines, start)
    }

    private fun blockFrom(
        lines: List<String>,
        start: Int,
    ): List<String> {
        val indent = indentOf(lines[start])
        val rest = lines.drop(start + 1)
        val end = rest.indexOfFirst { it.isNotBlank() && indentOf(it) <= indent && it.trim().startsWith("- ") }
        return listOf(lines[start]) + (if (end < 0) rest else rest.take(end))
    }

    /** The entries of the `files: |` block scalar: non-blank lines indented deeper than the key. */
    private fun filesList(block: List<String>): List<String> {
        val at = block.indexOfFirst { it.trim() == "files: |" }
        assertTrue(at >= 0, "$RELEASE_WORKFLOW: the publish step has no `files: |` list")
        val indent = indentOf(block[at])
        return block
            .drop(at + 1)
            .takeWhile { it.isBlank() || indentOf(it) > indent }
            .filter { it.isNotBlank() }
            .map { it.trim() }
    }

    private fun indentOf(line: String): Int = line.length - line.trimStart().length

    /** A minimal release job in the guarded order, or with the checksum line moved above the staging line. */
    private fun syntheticRelease(checksumBeforeStaging: Boolean): List<String> {
        val staging = "          bappAsset=\"$BAPP_ASSET_LINE\""
        val checksum = "            sha256sum \"\$f\" > \"\$f.sha256\""
        return listOf(
            "jobs:",
            "  release:",
            "    steps:",
            "      - run: ./gradlew ktlintCheck detekt --no-daemon",
            "      - run: ./gradlew test fullTest nightlyRegressionTest nightlyRegressionFullTest edtGuardWithoutAssertionsTest unloadLeakTest",
            "      - run: ./gradlew bappJar fullJar storeJarContentTest --no-daemon",
            "      - run: ./gradlew cyclonedxBom --no-daemon --no-configuration-cache",
            "      - run: |",
        ) +
            (if (checksumBeforeStaging) listOf(checksum, staging) else listOf(staging, checksum)) +
            listOf(
                "          sha256sum -c ./*.sha256",
                "      - uses: $PUBLISH_ACTION@v3",
            )
    }

    private companion object {
        const val RELEASE_WORKFLOW = ".github/workflows/release.yml"
        const val STAGING_STEP = "Stage release assets (D-01)"
        const val PUBLISH_ACTION = "softprops/action-gh-release"
        const val CHECKSUM_STEP = "Compute SHA-256 checksums (D-03)"
        const val NOTES_STEP = "Write release notes (D-04)"
        const val NOTES_FILE = "build/release-notes/release_notes.md"
        const val HEREDOC_MARKER = "WHICH_JAR"
        const val README = "README.md"
        const val README_WARNING = "**Load only one build.**"

        /** The block has 6 non-blank lines today; fewer than this means the heredoc lost its content. */
        const val MIN_BLOCK_LINES = 5

        val REQUIRED_IN_BLOCK =
            listOf(
                "## Which JAR?",
                "Custom-AI-Agent-full-@VERSION@.jar",
                "Custom-AI-Agent-bapp-@VERSION@.jar",
                "generic MCP tools",
                "CLI backends",
                "./gradlew bappJar",
                "sha256sum -c",
                "bom.json",
                // CR-01: the bom.json line states the version-level superset claim the build checks (T-30-17).
                "at the version the BApp Store JAR packages",
                "only the full build ships",
            )

        /** Byte identity with the BApp Store, store isolation, or checksum authenticity (T-30-11). */
        val FORBIDDEN_IN_BLOCK = listOf("identical", "same bytes", "cannot load", "tamper", "authentic", "guarantee")

        /** The staging step's versioned store asset name, as written in the workflow. */
        const val BAPP_ASSET_LINE = "Custom-AI-Agent-bapp-\${VERSION}.jar"

        val TOKEN_SEPARATORS = Regex("[\\s`'\"(),|;&]+")

        /** `${{ github.ref }}` / `${{ github.ref_name }}` in any spacing. */
        val TAG_EXPRESSION = Regex("\\$\\{\\{\\s*github\\.(ref|ref_name)\\b")

        val PUBLISHED_FILES =
            listOf(
                "build/release/Custom-AI-Agent-full-*.jar",
                "build/release/Custom-AI-Agent-full-*.jar.sha256",
                "build/release/Custom-AI-Agent-bapp-*.jar",
                "build/release/Custom-AI-Agent-bapp-*.jar.sha256",
                "build/reports/sbom/bom.json",
            )
    }

    /** The guarded step order: lint, suites, inspection gate, SBOM, staging, checksums, verification, publish. */
    private val order =
        listOf(
            Marker("runs ktlintCheck and detekt (the PR lint job)") { gradleRuns("ktlintCheck", "detekt")(it) },
            Marker("runs both flavors' fast and heavy suites and the unload leak proof (LIFE-01 / SC1)") {
                gradleRuns(
                    "test",
                    "fullTest",
                    "nightlyRegressionTest",
                    "nightlyRegressionFullTest",
                    "edtGuardWithoutAssertionsTest",
                    "unloadLeakTest",
                )(it)
            },
            Marker("builds both JARs and runs storeJarContentTest (D-02)") {
                gradleRuns("bappJar", "fullJar", "storeJarContentTest")(it)
            },
            Marker("generates bom.json with cyclonedxBom, after the gate whose storeJarContentTest checks the SBOM alignment (CR-01)") {
                gradleRuns("cyclonedxBom")(it)
            },
            Marker("stages the versioned store asset `$BAPP_ASSET_LINE` (D-01)") { it.contains(BAPP_ASSET_LINE) },
            Marker("writes each checksum with `sha256sum \"\$f\"` (D-03)") { it.contains("sha256sum \"\$f\"") },
            Marker("verifies the checksums with `sha256sum -c` (D-03)") { it.contains("sha256sum -c") },
            Marker("publishes with $PUBLISH_ACTION") { it.contains(PUBLISH_ACTION) },
        )
}
