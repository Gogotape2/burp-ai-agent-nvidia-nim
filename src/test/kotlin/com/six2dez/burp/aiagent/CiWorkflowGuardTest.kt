package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Phase 30 (CI-01, ROADMAP SC1 and SC2): CI keeps building both JARs, running both flavors' suites and
 * inspecting the BApp Store JAR in the CI jobs themselves.
 *
 * `storeJarContentTest` (plan 30-01) only protects the store JAR if a workflow actually invokes it. The
 * workflows cannot run locally, so a deleted step, a dropped OS or a renamed Gradle task leaves every
 * local gate green while CI silently stops checking the JAR the BApp Store reviewer receives. This guard
 * reads the workflow text from disk (`.github/workflows` is the declared `workflowsStructuralInputs`
 * input of `test`) and pins each invocation per job.
 *
 * BOUND: plain text, no YAML parser (none is on the test classpath). A job is the lines from its
 * two-space-indented key to the next one; a command is a non-comment line holding `./gradlew` or
 * `for task in`; a pin is met when one command's token set holds every required token. A step that is
 * present but skipped by an `if:` is invisible to it; review owns that.
 */
class CiWorkflowGuardTest {
    @Test
    fun prGateBuildsBothJarsRunsBothSuitesAndInspectsTheStoreJarOnEveryOs() {
        val text = projectFile(BUILD_WORKFLOW).readLines()
        val messages =
            missingPins(
                BUILD_WORKFLOW,
                text,
                listOf(
                    Pin(PR_GATE_JOB, setOf("test", "fullTest"), "both flavors' fast suites, SC1"),
                    Pin(PR_GATE_JOB, setOf("edtGuardWithoutAssertionsTest"), "the assertions-disabled EDT guard, REL-05"),
                    Pin(PR_GATE_JOB, setOf("bappJar", "fullJar", "storeJarContentTest"), "both JARs and the store JAR inspection, CI-01 / SC2"),
                ),
            ).toMutableList()
        val live = jobBlock(BUILD_WORKFLOW, text, PR_GATE_JOB).filterNot { isComment(it) }
        PR_GATE_OSES.filter { os -> live.none { it.contains(os) } }.forEach {
            messages += "$BUILD_WORKFLOW / $PR_GATE_JOB: the OS matrix no longer lists $it (the inspection must run on all three OSes)"
        }
        STORE_REPORT_GLOBS.filter { glob -> live.none { it.trim() == glob } }.forEach {
            messages += "$BUILD_WORKFLOW / $PR_GATE_JOB: the test report upload no longer includes $it (a red inspection must be readable)"
        }
        assertTrue(messages.isEmpty(), "CI stopped checking the store JAR:\n" + messages.joinToString("\n"))
    }

    @Test
    fun theGuardedTaskNameIsTheOneTheBuildRegisters() {
        // Renaming the task in the build script must fail here, not silently orphan the workflow steps.
        assertTrue(
            projectFile(BUILD_SCRIPT).readText().contains("register<Test>(\"$INSPECTION_TASK\")"),
            "$BUILD_SCRIPT no longer registers the Test task `$INSPECTION_TASK` that the workflows invoke " +
                "by name. Rename the workflow invocations and this guard together.",
        )
    }

    @Test
    fun storeBuildAndNightlyRunTheInspection() {
        val inspection = setOf("bappJar", INSPECTION_TASK)
        val messages =
            missingPins(
                BUILD_WORKFLOW,
                projectFile(BUILD_WORKFLOW).readLines(),
                listOf(Pin(STORE_JOB, inspection, "the store JAR the store-build job uploads must be inspected, CI-01")),
            ) +
                missingPins(
                    NIGHTLY_WORKFLOW,
                    projectFile(NIGHTLY_WORKFLOW).readLines(),
                    listOf(Pin(NIGHTLY_JOB, inspection, "the nightly run builds and inspects the store JAR, CI-01")),
                )
        assertTrue(messages.isEmpty(), "CI stopped checking the store JAR:\n" + messages.joinToString("\n"))
    }

    @Test
    fun coverageDryRunGuardReadsTheInspectionTaskGraph() {
        val messages =
            missingPins(
                BUILD_WORKFLOW,
                projectFile(BUILD_WORKFLOW).readLines(),
                listOf(
                    Pin(COVERAGE_JOB, setOf("--dry-run", INSPECTION_TASK), "the dry run must read the inspection task's graph"),
                    Pin(COVERAGE_JOB, setOf("for", "task", "in", INSPECTION_TASK), "the guard loop must require the inspection task"),
                    Pin(
                        COVERAGE_JOB,
                        setOf("test", "jacocoTestCoverageVerification", "jacocoMcpTreeCoverageVerification"),
                        "the full suite and the coverage floors stay",
                    ),
                ),
            )
        assertTrue(messages.isEmpty(), "The coverage job's guard or floors lost an invocation:\n" + messages.joinToString("\n"))
    }

    @Test
    fun ciRunsOnPushAndPullRequestToMainWithAReadOnlyToken() {
        val lines = projectFile(BUILD_WORKFLOW).readLines()
        val jobsAt = lines.indexOfFirst { it.trimEnd() == "jobs:" }
        assertTrue(jobsAt >= 0, "$BUILD_WORKFLOW has no top-level `jobs:` line")
        val header = lines.take(jobsAt).filterNot { isComment(it) || it.isBlank() }
        val trimmed = header.map { it.trim() }
        val messages = mutableListOf<String>()
        listOf("push:", "pull_request:").filter { it !in trimmed }.forEach {
            messages += "$BUILD_WORKFLOW: the `on:` block no longer has `$it` (SC1: CI on push to main and on PRs)"
        }
        val mainBranches = trimmed.count { it == "branches: [ main ]" }
        if (mainBranches != 2) {
            messages += "$BUILD_WORKFLOW: expected `branches: [ main ]` under both push and pull_request, found $mainBranches"
        }
        val permissionsAt = header.indexOfFirst { it.trimEnd() == "permissions:" }
        if (permissionsAt < 0 || header.getOrNull(permissionsAt + 1)?.trim() != "contents: read") {
            messages += "$BUILD_WORKFLOW: no top-level `permissions:` block with `contents: read` (read-only GITHUB_TOKEN, T-30-06)"
        }
        assertTrue(messages.isEmpty(), messages.joinToString("\n"))
    }

    @Test
    fun aMissingInvocationIsReportedNamingFileAndJob() {
        // Fail-first proof: if the matcher stopped reporting a missing token (or counted a comment as a
        // command), the whole-file pins above would pass over a workflow that no longer inspects the JAR.
        val pins = listOf(Pin(PR_GATE_JOB, setOf("bappJar", "fullJar", INSPECTION_TASK), "synthetic"))
        val missing = missingPins("synthetic.yml", syntheticWorkflow("./gradlew bappJar fullJar --no-daemon"), pins)
        assertEquals(1, missing.size, "expected exactly one message for the missing inspection, got $missing")
        assertTrue(
            missing.single().startsWith("synthetic.yml / $PR_GATE_JOB:") && missing.single().contains(INSPECTION_TASK),
            "the message must name the file, the job and the missing task: ${missing.single()}",
        )
        assertEquals(
            emptyList<String>(),
            missingPins("synthetic.yml", syntheticWorkflow("./gradlew bappJar fullJar $INSPECTION_TASK --no-daemon"), pins),
            "a command that runs every pinned token must not be reported",
        )
    }

    private data class Pin(
        val job: String,
        val tokens: Set<String>,
        val why: String,
    )

    /** A pr-gate job whose only mention of the inspection task is a comment line, so it must not count. */
    private fun syntheticWorkflow(command: String): List<String> =
        listOf(
            "on:",
            "  push:",
            "jobs:",
            "  $PR_GATE_JOB:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      # $INSPECTION_TASK is only mentioned in this comment",
            "      - run: $command",
            "  other:",
            "    steps:",
            "      - run: ./gradlew $INSPECTION_TASK --no-daemon",
        )

    private fun projectFile(relative: String): File {
        val file = File(SourceRoots.layout().projectDir, relative)
        assertTrue(file.isFile, "expected $relative at ${file.absolutePath}")
        return file
    }

    private fun isComment(line: String): Boolean = line.trim().startsWith("#")

    /** Lines of [jobId] under `jobs:`, from its two-space-indented key up to the next job key. */
    private fun jobBlock(
        fileName: String,
        lines: List<String>,
        jobId: String,
    ): List<String> {
        val jobsAt = lines.indexOfFirst { it.trimEnd() == "jobs:" }
        assertTrue(jobsAt >= 0, "$fileName has no top-level `jobs:` line")
        val body = lines.drop(jobsAt + 1)
        val start = body.indexOfFirst { it.trimEnd() == "  $jobId:" }
        assertTrue(start >= 0, "$fileName / $jobId: the job is missing")
        val rest = body.drop(start + 1)
        val end = rest.indexOfFirst { JOB_KEY.matches(it.trimEnd()) || TOP_LEVEL_KEY.matches(it.trimEnd()) }
        return if (end < 0) rest else rest.take(end)
    }

    private fun commandLines(block: List<String>): List<String> = block.filter { !isComment(it) && (it.contains("./gradlew") || it.contains("for task in")) }

    private fun tokens(line: String): Set<String> = line.split(TOKEN_SEPARATORS).filter { it.isNotEmpty() }.toSet()

    /** One message per pin no command line of its job satisfies: `<file> / <job>: no command runs <tokens> (<why>)`. */
    private fun missingPins(
        fileName: String,
        text: List<String>,
        pins: List<Pin>,
    ): List<String> =
        pins
            .filter { pin -> commandLines(jobBlock(fileName, text, pin.job)).none { tokens(it).containsAll(pin.tokens) } }
            .map { "$fileName / ${it.job}: no command runs ${it.tokens.joinToString(" ")} (${it.why})" }

    private companion object {
        const val BUILD_SCRIPT = "build.gradle.kts"
        const val BUILD_WORKFLOW = ".github/workflows/build.yml"
        const val NIGHTLY_WORKFLOW = ".github/workflows/nightly-regression.yml"
        const val PR_GATE_JOB = "pr-gate"
        const val COVERAGE_JOB = "coverage"
        const val STORE_JOB = "store-build"
        const val NIGHTLY_JOB = "nightly-regression"
        const val INSPECTION_TASK = "storeJarContentTest"

        val PR_GATE_OSES = listOf("ubuntu-latest", "macos-latest", "windows-latest")
        val STORE_REPORT_GLOBS =
            listOf(
                "build/reports/tests/$INSPECTION_TASK/**",
                "build/test-results/$INSPECTION_TASK/**",
            )

        val JOB_KEY = Regex("^ {2}[A-Za-z0-9_.-]+:.*$")
        val TOP_LEVEL_KEY = Regex("^[A-Za-z0-9_.-]+:.*$")
        val TOKEN_SEPARATORS = Regex("[\\s\"'();$=|<>]+")
    }
}
