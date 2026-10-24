import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "2.1.21"
    kotlin("plugin.serialization") version "2.1.21"
    id("com.gradleup.shadow") version "8.3.11"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"
    id("org.cyclonedx.bom") version "1.10.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    jacoco
}

group = "com.six2dez.burp"
version = "1.0.0-nim.16"

repositories {
    mavenCentral()
    maven("https://www.jetbrains.com/intellij-repository/releases")
    maven("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
}

dependencies {
    // Burp Montoya API (compileOnly, Burp provides it at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // JSON
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.1")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.22.1")

    // HTTP client (Ollama + webhooks)
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("org.jsoup:jsoup:1.23.2")

    // MCP Server (Ktor + MCP SDK)
    implementation("io.modelcontextprotocol:kotlin-sdk:0.5.0")
    implementation("io.ktor:ktor-server-core:3.1.3")
    implementation("io.ktor:ktor-server-netty:3.1.3")
    implementation("io.ktor:ktor-server-cors:3.1.3")
    implementation("io.ktor:ktor-server-sse:3.1.3")
    implementation("io.ktor:ktor-server-content-negotiation:3.1.3")
    implementation("io.ktor:ktor-serialization-kotlinx-json:3.1.3")
    // Phase 16: Ktor CLIENT modules (pin to 3.1.3 to match server-side Ktor family)
    implementation("io.ktor:ktor-client-core:3.1.3")
    implementation("io.ktor:ktor-client-cio:3.1.3")
    // kotlin-logging: transitive via kotlin-sdk:0.5.0 StdioClientTransport; declared explicitly to pin version
    implementation("io.github.oshai:kotlin-logging-jvm:7.0.7")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-io-core:0.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    // Logging façade (we keep it minimal; Burp logs are also used)
    implementation("org.slf4j:slf4j-api:2.0.16")
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.2")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.4.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:5.4.0")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

// -PstoreBuild=true produces the BApp Store artifact (native tools only).
// Default (false) produces the full GitHub release artifact.
val storeBuild = providers.gradleProperty("storeBuild").orNull == "true"

abstract class GenerateBuildFlagsTask : DefaultTask() {
    @get:Input
    abstract val storeBuildFlag: Property<Boolean>

    @get:Input
    abstract val version: Property<String>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val pkgDir =
            outputDir
                .get()
                .asFile
                .resolve("com/six2dez/burp/aiagent")
                .also { it.mkdirs() }
        pkgDir.resolve("BuildFlags.kt").writeText(
            """
package com.six2dez.burp.aiagent

object BuildFlags {
    const val STORE_BUILD = ${storeBuildFlag.get()}
    const val VERSION = "${version.get()}"
}
            """.trimIndent() + "\n",
        )
    }
}

val generateBuildFlags by tasks.registering(GenerateBuildFlagsTask::class) {
    group = "build"
    description = "Generates BuildFlags.kt with a compile-time store-build flag and the project version"
    storeBuildFlag.set(storeBuild)
    // SEC-05 / P11: capture the project version at CONFIGURATION time. gradle.properties sets
    // org.gradle.configuration-cache=true, so reading any Project API (including project.version)
    // from inside @TaskAction generate() would fail the build. The Property carries the captured
    // value into execution instead.
    version.set(project.version.toString())
    outputDir.set(layout.buildDirectory.dir("generated/buildflags"))
}

sourceSets.main {
    // Pass the task's own outputDir through the TaskProvider — Gradle infers the dependency
    // for any task consuming this source directory (including runKtlintCheckOverMainSourceSet).
    kotlin.srcDir(generateBuildFlags.flatMap { it.outputDir })
}

tasks.withType<KotlinCompile> {
    dependsOn(generateBuildFlags)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(listOf("-Xjsr305=strict"))
    }
}

tasks.jar {
    enabled = false
}

tasks.shadowJar {
    if (storeBuild) {
        archiveBaseName.set("Custom-AI-Agent")
    } else {
        archiveBaseName.set("Custom-AI-Agent-full")
    }
    archiveClassifier.set("")
    mergeServiceFiles()
    relocate("org.jsoup", "com.six2dez.burp.aiagent.shaded.jsoup")
    isZip64 = true

    // Shadow JAR should include all runtime dependencies
    configurations = listOf(project.configurations.runtimeClasspath.get())
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("-ea", "-Djava.awt.headless=true") // Enable JVM assertions so EDT assert() fires in CI (REL-01 SC1 gate)
    // The headless flag above serves the Phase 22 SC4 harness (ChatPanelTestHarness), which
    // constructs a REAL ChatPanel and drives its REAL Send button. ubuntu-latest is headless anyway;
    // forcing the flag makes a developer Mac behave identically instead of silently taking the
    // windowed path and hiding a CI-only failure.
    // The generated BuildFlags.STORE_BUILD offers no other seam a test can compare against, so
    // McpBuildFlagsVersionTest used to assert a literal false — which made `-PstoreBuild=true`, the
    // BApp Store artifact build path, fail its own test suite. Passing the already-resolved
    // `storeBuild` Boolean (configuration-cache-safe, exactly as tasks.shadowJar consumes it) lets
    // the test assert that the generated constant tracks the Gradle property under either build.
    systemProperty("storeBuild.expected", storeBuild.toString())
    // SEC-06 / SC1: DecisionsAdrTest reads these two files from disk at runtime rather than from the
    // compiled classpath, so Gradle cannot infer them. Without declaring them, a change to EITHER is
    // invisible to the up-to-date check and the build cache — and a commit that edits only DECISIONS.md,
    // or only the SecTier KDoc, produces byte-identical compiled output and therefore an identical
    // cache key. The test task would be restored from cache and the guard would never run, in exactly
    // the case it exists to catch. Measured: mutating the AUTO sentence left `./gradlew test` GREEN
    // until `cleanTest` forced a re-run.
    inputs
        .file("DECISIONS.md")
        .withPropertyName("adrRecord")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/mcp/McpToolCatalog.kt")
        .withPropertyName("secTierKdocSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // DOC-03 / SC5 / SC6: SecurityDocsTest reads these six markdown files from disk — the same
    // stale-cache defect as the DECISIONS.md declaration above, in its purest form. A
    // documentation-only edit produces BYTE-IDENTICAL compiled output, so without these declarations
    // the cache key is unchanged and the guard is served from cache in exactly the commit that breaks
    // it. Measured for this build: with `securityPolicy` declared, mutating one asserted word in
    // SECURITY.md re-executed `:test` (11 tests, 1 failed) instead of reporting UP-TO-DATE.
    inputs
        .file("SECURITY.md")
        .withPropertyName("securityPolicy")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("README.md")
        .withPropertyName("readmeClaims")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("SPEC.md")
        .withPropertyName("specClaims")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/ui-safety-guide.md")
        .withPropertyName("uiSafetyRunbook")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/anthropic-backend.md")
        .withPropertyName("anthropicBackendDoc")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs
        .file("docs/external-mcp-servers.md")
        .withPropertyName("externalMcpDoc")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // SEC-06 / SC5 / CR-02: ToolApprovalGateVisibilityTest reads this file from disk to pin
    // `approvedOrigin` as private and `ModelApproved` as file-private, for the same reason and with the
    // same caveat as the two declarations above. A visibility widening does change the compiled output,
    // but a comment-only edit to the file does not — and this guard's source-text half asserts on text
    // that includes the surrounding declarations. Undeclared, that edit produces an identical cache key
    // and the test task is served from cache with the guard never running (the 22-09 defect).
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/mcp/ToolApprovalGate.kt")
        .withPropertyName("originVisibilitySource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // SEC-06 / SC4 / WR-09: ChatPanelToolGateTest reads this file from disk in `functionBody` to make
    // the two structural assertions it cannot drive headlessly — the modal-dialog path in
    // `userDialogPathIsNotDoublePrompted`, and `resolvePending`'s no-followup rule in
    // `shutdownResolvesAllPendingDecisionsWithoutSendingATurn`. Same defect as the three declarations
    // above, and the one 22-09 measured on its own ADR guard: an edit that changes the source text but
    // not the compiled bytecode — a comment replaced in place, a string reflowed — produces an
    // identical cache key, so the test task is served from cache and the structural guard never runs in
    // exactly the case it exists to catch.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/ChatPanel.kt")
        .withPropertyName("chatPanelStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / Rule C-2: SettingsSaveAsyncTest reads this file from disk in
    // `restoreDefaultsSource` to assert the one ordering it cannot drive headlessly — the
    // restore-defaults path opens with `JOptionPane.showConfirmDialog`, and `getRootFrame()` throws
    // `HeadlessException`. Same defect as the four declarations above: moving
    // `"Defaults restored and applied."` back out of the completion callback changes the source text
    // but can leave the compiled output of the surrounding class close enough that the cache key
    // survives, so the guard would be served from cache and never run in exactly the case it exists
    // to catch.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelActions.kt")
        .withPropertyName("settingsActionsStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / CR-02: SettingsPersistQueueTest reads this file from disk in
    // `everyMainTabSettingsWriteGoesThroughThePersistQueue` to assert the four mention counts pinned in
    // the KDoc ledger above `MainTab.persistSettings` — that every enumerated settings write goes
    // through the persist queue rather than calling settingsRepo.save() inline on the EDT. Same defect
    // as the five declarations above: reverting one call site back to an inline save changes the source
    // text but leaves the surrounding compiled output close enough that the cache key can survive, so
    // the guard would be served from cache and never run in exactly the case it exists to catch (the
    // 22-09 stale-cache defect).
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/MainTab.kt")
        .withPropertyName("mainTabPersistSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-05 / SC4 / Rule T-3: SettingsSaveAsyncTest's corrected structural assertion now reads THIS
    // file too — the narrowed claim is that applySettingsToUi's component writes stay on the EDT while
    // its three host notifications are suppressed at the restore call site, and the `notifyHosts` guard
    // that makes that true lives here. Same 22-09 stale-cache defect as the six declarations above:
    // deleting the guard changes the source text but can leave the cache key intact.
    inputs
        .file("src/main/kotlin/com/six2dez/burp/aiagent/ui/SettingsPanelSettingsIO.kt")
        .withPropertyName("settingsIoStructuralSource")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    // REL-06 / SC1 / REL-07: SchedulerGuardCoverageTest walks the WHOLE main source tree from disk and
    // asserts that only three files call a recurring schedule directly. A per-file declaration like the
    // seven above would be blind to a scheduler introduced in an eighth, undeclared file — which is the
    // exact defect the allowlist exists to catch, so the declaration has to be as wide as the assertion.
    // This is the first `inputs.dir` in this build and it deliberately supersedes per-file entries for
    // every Phase 24 structural assertion: REL-06-D here, REL-07-D and REL-07-F on CliBackend.kt, and
    // REL-07-G on App.kt / ActiveAiScanner.kt / AgentSupervisor.kt. Accepted cost: `tasks.test` re-runs
    // on any main-source edit. The defect it prevents is the measured 22-09 one recorded at :170-176 —
    // mutating source text without changing bytecode yields an identical cache key, so the guard is
    // served from cache in exactly the commit that breaks it.
    inputs
        .dir("src/main/kotlin")
        .withPropertyName("mainSourceTreeStructuralInputs")
        .withPathSensitivity(PathSensitivity.RELATIVE)
    val excludeHeavyTests =
        (project.findProperty("excludeHeavyTests") as? String)
            ?.trim()
            ?.equals("true", ignoreCase = true) == true
    if (excludeHeavyTests) {
        filter {
            excludeTestsMatching("*IntegrationTest")
            excludeTestsMatching("*ConcurrencyTest")
            excludeTestsMatching("*BackpressureTest")
            excludeTestsMatching("*RestartPolicyTest")
            excludeTestsMatching("*SupervisionTest") // WR-03: 30s coerced-timeout floor — excluded from fast PR gate
        }
    }
}

// REL-05 / SC1 / S-10: `tasks.test` above enables `-ea`, so a green McpToolExecutorEdtGuardTest there
// proves the guard throws in a JVM where the debug-time assertion facility is ON — which is not the JVM
// SC1 is about. Shipped Burp runs WITHOUT `-ea`, and SC1's whole objection to the existing ChatPanel
// assertion is that it is a no-op there. This task re-runs that one class with assertions DISABLED, so
// "the guard fires where it matters" is demonstrated rather than asserted.
//
// WR-11 corrected the second half of this comment. It stays out of the `check` lifecycle task on
// purpose — `check` is the fast path and this is a deliberate, separately named gate — AND it is
// invoked explicitly by `.github/workflows/build.yml`'s pr-gate step on all three OSes and by
// `.github/workflows/nightly-regression.yml`. The justification it used to carry, that it "duplicates
// coverage the fast PR gate already has", was wrong in exactly the way that mattered: the fast PR gate
// runs with `-ea`, where an `assert`-based guard is equally green, so reverting `check(...)` to
// `assert(...)` in McpToolExecutorImpl would have left every automated gate passing.
// Run it locally with: ./gradlew edtGuardWithoutAssertionsTest
tasks.register<Test>("edtGuardWithoutAssertionsTest") {
    description = "Runs the executor's EDT door guard with JVM assertions disabled (REL-05 / SC1)."
    group = "verification"
    useJUnitPlatform()
    val testSourceSet = sourceSets.test.get()
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    // `-da`, and no `-ea` anywhere: this is the flag the whole task exists for.
    jvmArgs("-da", "-Djava.awt.headless=true")
    systemProperty("storeBuild.expected", storeBuild.toString())
    filter {
        includeTestsMatching("*McpToolExecutorEdtGuardTest")
    }
}

tasks.register<Test>("nightlyRegressionTest") {
    description = "Runs integration, concurrency, and resilience suites intended for nightly validation."
    group = "verification"
    useJUnitPlatform()
    filter {
        includeTestsMatching("*IntegrationTest")
        includeTestsMatching("*ConcurrencyTest")
        includeTestsMatching("*BackpressureTest")
        includeTestsMatching("*RestartPolicyTest")
        includeTestsMatching("*SupervisionTest") // WR-03: still runs in nightly regression
    }
}

ktlint {
    version.set("1.5.0")
    android.set(false)
    // Strict by default: fails unless -PktlintLenient=true is passed as an escape hatch.
    // Mass-format commit (style(sc3)) preceded this gate-flip — codebase is clean.
    ignoreFailures.set(
        (project.findProperty("ktlintLenient") as? String)?.equals("true", ignoreCase = true) == true,
    )
    reporters {
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.PLAIN)
        reporter(org.jlleitschuh.gradle.ktlint.reporter.ReporterType.CHECKSTYLE)
    }
    filter {
        exclude("**/build/**")
        exclude("**/generated/**")
    }
}

detekt {
    buildUponDefaultConfig = true // extend defaults, not replace
    allRules = false // only default ruleset rules
    baseline = file("detekt-baseline.xml") // committed baseline; generate with: ./gradlew detektBaseline
    parallel = true
    config.setFrom(files("detekt.yml")) // project-specific overrides
}

tasks.withType<Test> {
    finalizedBy(tasks.named("jacocoTestReport"))
}

tasks.named<JacocoReport>("jacocoTestReport") {
    dependsOn(tasks.named("test"))
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.named<org.cyclonedx.gradle.CycloneDxTask>("cyclonedxBom") {
    includeConfigs.set(listOf("runtimeClasspath"))
    outputFormat.set("json")
    outputName.set("bom")
    destination.set(
        layout.buildDirectory
            .dir("reports/sbom")
            .get()
            .asFile,
    )
}
