package com.six2dez.burp.aiagent.backends.cli

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

/**
 * REL-07 / SC5 — the acceptance suite for [CliTempFileRegistry], the bounded live-file registry that
 * replaces the JDK's per-invocation exit-time deletion registration in `CliBackend` (CONTEXT.md D-01
 * through D-04).
 *
 * **Naming constraint (hard).** `build.gradle.kts` excludes `*IntegrationTest`, `*ConcurrencyTest`,
 * `*BackpressureTest`, `*RestartPolicyTest` and `*SupervisionTest` under `-PexcludeHeavyTests=true`,
 * which is exactly what `.github/workflows/build.yml` passes on the PR gate. `CliBackendTempFileTest`
 * is the approved name and does not match any of them — recorded here because
 * `CliTempFileRegistryConcurrencyTest` is the natural name for a suite that drives a thread-safe
 * registry and would have made this suite silently stop running on the PR gate.
 *
 * **What this file replaced, and why it was replaced rather than inverted.** Two tests named
 * `uvPromptDeleteOnExitIsRegistered` and `codexOutputDeleteOnExitIsRegistered` used to live here with
 * a reflective helper that read the JDK's internal exit-hook file set. They were measured vacuous, not
 * blocking: each created its OWN temp file under a different prefix, neither referenced `CliBackend`
 * at all, and the helper's reflection raises `InaccessibleObjectException` on the project's JDK 21 —
 * a `RuntimeException`, which the helper's own `catch (_: Exception) { true }` converted into a pass.
 * They were incapable of ever failing. SC5 therefore had zero real coverage before this rewrite.
 *
 * **No test in this file reflects into `java.base`.** That technique is dead on every JDK 16 and
 * later and fails open by construction; `24-VALIDATION.md` §Assertions Explicitly Ruled Out records
 * it. The registry is `internal` (D-02) precisely so its state is directly observable in pure JVM,
 * with no subprocess and no reflection.
 *
 * **The two surviving tests are a control only in the weakest sense.** `uvPromptTempFileIsCleanedUpAfterFailure`
 * and `codexOutputTempFileIsCleanedUpAfterFailure` create and delete their own files and prove that
 * `File.delete()` in a `finally` block works. They are NOT coverage of `CliBackend`'s own `finally`
 * path — nothing here drives that code. They are kept because they still pin the shape D-01 preserves
 * and they must stay green across this rewrite, which is a useful regression signal and nothing more.
 */
class CliBackendTempFileTest {
    // -------- helper: list current temp files matching a prefix --------

    private fun tempDir(): File = File(System.getProperty("java.io.tmpdir"))

    private fun tempFilesMatching(prefix: String): Set<String> =
        tempDir()
            .listFiles()
            ?.filter { it.name.startsWith(prefix) }
            ?.map { it.absolutePath }
            ?.toSet()
            ?: emptySet()

    // -------- registry fixture --------

    private lateinit var workDir: File

    /**
     * Each test starts from an empty registry with no hook reference, and ends with the hook removed
     * from the JVM. `resetForTests()` deliberately does NOT unregister an already-registered hook, so
     * the `shutdown()` in the teardown below is what keeps this suite from leaving hooks behind.
     */
    @BeforeEach
    fun setUp() {
        CliTempFileRegistry.resetForTests()
        workDir = Files.createTempDirectory("cli-temp-registry-test").toFile()
    }

    @AfterEach
    fun tearDown() {
        CliTempFileRegistry.shutdown()
        workDir.deleteRecursively()
    }

    private fun newFile(name: String): File =
        File(workDir, name).also {
            it.writeText("payload")
        }

    // -------- behavioral test: finally-cleanup proves no leak --------

    /**
     * Create a real temp file using the same createTempFile call sites as CliBackend, then
     * simulate the failure-path (try/catch throwing before the file is used).
     * The file is explicitly deleted in the finally block, proving the contract.
     * This test validates the behavior that CliBackendTempFileTest must guard against regression.
     */
    @Test
    fun uvPromptTempFileIsCleanedUpAfterFailure() {
        val before = tempFilesMatching("burp_uv_prompt_")

        // Simulate the production code path: create the temp file, then throw before use.
        var promptFile: File? = null
        try {
            val tFile = File.createTempFile("burp_uv_prompt_", ".txt")
            promptFile = tFile
            throw RuntimeException("simulated write failure")
        } catch (_: RuntimeException) {
            // expected — mirrors the production catch in CliBackend's large-prompt branch
        } finally {
            try {
                promptFile?.delete()
            } catch (_: Exception) {
                // INTENTIONAL: mirrors the production finally block's bare cleanup catch
            }
        }

        val after = tempFilesMatching("burp_uv_prompt_")
        assertEquals(before, after, "burp_uv_prompt_ temp file leaked after simulated failure")
    }

    @Test
    fun codexOutputTempFileIsCleanedUpAfterFailure() {
        val before = tempFilesMatching("burp-ai-agent-codex")

        var outputFile: File? = null
        try {
            val tFile = File.createTempFile("burp-ai-agent-codex", ".txt")
            outputFile = tFile
            throw RuntimeException("simulated processing failure")
        } catch (_: RuntimeException) {
            // expected
        } finally {
            try {
                outputFile?.delete()
            } catch (_: Exception) {
                // INTENTIONAL: mirrors the production finally block's bare cleanup catch
            }
        }

        val after = tempFilesMatching("burp-ai-agent-codex")
        assertEquals(before, after, "burp-ai-agent-codex temp file leaked after simulated failure")
    }

    // -------- REL-07-E: the registry seam (D-01, D-02) --------

    /**
     * REL-07-E — registration is set-membership on the absolute path, so a retry that re-registers the
     * same file cannot inflate the registry. This is the boundary half of A-EDGE-4: the registry has no
     * numeric cap, its bound is structural.
     */
    @Test
    fun registeringTheSameFileTwiceStillYieldsOneEntry() {
        val first = newFile("prompt-a.txt")
        val second = newFile("prompt-b.txt")

        CliTempFileRegistry.register(first)
        assertEquals(1, CliTempFileRegistry.sizeForTests(), "One registered file must be one entry.")

        CliTempFileRegistry.register(first)
        assertEquals(
            1,
            CliTempFileRegistry.sizeForTests(),
            "Registering the SAME file twice must still be one entry. If a retry could add a second " +
                "entry the registry would grow with invocation count, which is exactly the unbounded " +
                "growth D-01 exists to remove (REL-07 / SC5, threat T-24-15).",
        )

        CliTempFileRegistry.register(second)
        assertEquals(
            2,
            CliTempFileRegistry.sizeForTests(),
            "Two DIFFERENT in-flight files must be two entries — the bound is one entry per in-flight " +
                "call, not one entry overall.",
        )
    }

    /**
     * REL-07-E — deregistration is what returns the registry to empty when a call finishes, and it must
     * tolerate a path it never held. `CliBackend`'s `finally` runs unconditionally, including on paths
     * where the optional codex output file or the optional large-prompt file was never created.
     */
    @Test
    fun deregisteringReturnsToEmptyAndTolerantOfUnknownFiles() {
        val file = newFile("prompt-c.txt")
        CliTempFileRegistry.register(file)

        CliTempFileRegistry.deregister(file)
        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "Deregistering the only registered file must return the registry to empty.",
        )

        CliTempFileRegistry.deregister(newFile("never-registered.txt"))
        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "Deregistering a file that was never registered must be a no-op, not an error: the " +
                "production finally block runs on paths where the file was never created.",
        )
    }

    /**
     * REL-07-E — the drain is the safety net's actual work: it deletes what the `finally` block did not
     * get to. This is the one case a hook uniquely covers, a clean Burp quit while a CLI call is in
     * flight.
     */
    @Test
    fun drainDeletesAStillRegisteredFileAndEmptiesTheRegistry() {
        val file = newFile("in-flight.txt")
        CliTempFileRegistry.register(file)
        assertTrue(file.isFile, "Fixture precondition: the file exists on disk before the drain.")

        CliTempFileRegistry.drain()

        assertFalse(
            file.exists(),
            "The drain must delete a file still registered when the extension shuts down. That is the " +
                "only case the safety net exists for (REL-07 / SC5).",
        )
        assertEquals(0, CliTempFileRegistry.sizeForTests(), "The drain must leave the registry empty.")
    }

    /**
     * REL-07-E (A-EDGE-4, idempotence) — both the `finally` block and the drain may run for the same
     * file. A double delete must not surface as an error; this is a stated D-03 requirement, not a
     * nicety.
     */
    @Test
    fun drainIsIdempotentWhenTheFinallyPathAlreadyDeletedTheFile() {
        val file = newFile("already-gone.txt")
        CliTempFileRegistry.register(file)
        assertTrue(file.delete(), "Fixture precondition: the finally path deletes the file first.")

        CliTempFileRegistry.drain()

        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "A drain over a file the finally block already deleted must still empty the registry and " +
                "must not throw — both mechanisms legitimately run for the same file (D-03).",
        )
    }

    /** REL-07-E (A-EDGE-4, the empty boundary) — draining an empty registry is a no-op. */
    @Test
    fun drainOnAnEmptyRegistryIsANoOp() {
        assertEquals(0, CliTempFileRegistry.sizeForTests(), "Fixture precondition: the registry is empty.")

        CliTempFileRegistry.drain()

        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "Draining an empty registry must be a no-op — a Burp session that never used a CLI backend " +
                "reaches this path on every unload.",
        )
    }

    /**
     * REL-07-E — the direct SC5 assertion. Ten complete calls, each registering its temp file and then
     * deregistering it the way the `finally` block does, must leave the registry empty. Under the
     * mechanism D-01 removes the equivalent count would be ten retained path strings for the life of
     * the Burp JVM, with no removal API.
     */
    @Test
    fun tenCompleteCallsLeaveTheRegistryEmpty() {
        repeat(SIMULATED_CALL_COUNT) { index ->
            val file = newFile("call-$index.txt")
            CliTempFileRegistry.register(file)
            file.delete()
            CliTempFileRegistry.deregister(file)
        }

        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "After $SIMULATED_CALL_COUNT completed calls the registry must be empty. A non-zero count " +
                "means the registry grows with lifetime invocation count instead of being bounded by " +
                "in-flight concurrency, which is the defect REL-07 / SC5 exists to close.",
        )
    }

    /**
     * REL-07-E — a temp file whose delete FAILS must keep its entry, so the drain can retry it.
     *
     * `File.delete()` reports failure by returning `false`; it does not throw. On Windows it returns
     * `false` while the CLI child process still holds the handle, and `CliBackend`'s `finally` block
     * runs immediately after `destroyForcibly()`, so the handle is not guaranteed to be released yet.
     * A deregister that ran anyway would leave the file with no owner at all — off the disk's cleanup
     * path and out of this registry — and neither the exit hook nor `App.shutdown()`'s drain could
     * ever sweep it. The abandoned file is `burp_uv_prompt_*.txt`, which holds the full prompt, on the
     * one platform where owner-only permissions are also skipped.
     *
     * The fixture is a NON-EMPTY DIRECTORY, whose `delete()` returns `false` deterministically on every
     * platform. Nothing here reflects into `java.base`; `24-VALIDATION.md` rules that technique out.
     */
    @Test
    fun aFileWhoseDeleteFailsKeepsItsEntryForTheDrainToRetry() {
        val undeletable = File(workDir, "still-held-by-the-child").also { it.mkdir() }
        File(undeletable, "child.txt").writeText("payload")
        CliTempFileRegistry.register(undeletable)

        CliTempFileRegistry.deleteAndDeregister(undeletable)

        assertTrue(
            undeletable.exists(),
            "Fixture precondition: delete() must genuinely have failed here, or this test asserts nothing.",
        )
        assertEquals(
            1,
            CliTempFileRegistry.sizeForTests(),
            "A file whose delete() returned false must KEEP its entry. Dropping it abandons the file: " +
                "the exit hook and App.shutdown()'s drain both work off this registry, so an entry " +
                "removed here is a temp file — holding the full prompt — left in the shared OS temp " +
                "directory with nothing left to sweep it (REL-07 / SC5, D-01).",
        )
    }

    /**
     * REL-07-E — the other two arms of the same seam: a delete that succeeds, and the two no-op inputs
     * `CliBackend`'s `finally` block genuinely reaches (a file another path already deleted, and a
     * `null` for an optional temp file that was never created).
     */
    @Test
    fun aSuccessfulDeleteDeregistersAndAnAlreadyGoneOrNullFileIsANoOp() {
        val file = newFile("cleaned-up.txt")
        CliTempFileRegistry.register(file)

        CliTempFileRegistry.deleteAndDeregister(file)

        assertFalse(file.exists(), "The normal path must still delete the file — this is the PRIMARY cleanup path.")
        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "A successful delete must return the registry to empty, or the bound becomes lifetime " +
                "invocation count instead of in-flight concurrency (D-01).",
        )

        val alreadyGone = newFile("already-gone-elsewhere.txt")
        CliTempFileRegistry.register(alreadyGone)
        assertTrue(alreadyGone.delete(), "Fixture precondition: another path deleted the file first.")

        CliTempFileRegistry.deleteAndDeregister(alreadyGone)
        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "A file that is already off the disk must still be deregistered. Retaining it would leak an " +
                "entry on every double-cleanup, which D-03 requires to be idempotent.",
        )

        CliTempFileRegistry.deleteAndDeregister(null)
        assertEquals(
            0,
            CliTempFileRegistry.sizeForTests(),
            "null must be a no-op: the production finally block runs on paths where the optional prompt " +
                "file or codex output file was never created.",
        )
    }

    /**
     * D-03 — the hook is registered lazily on first temp-file creation, never eagerly. A Burp session
     * that never uses a CLI backend must pay nothing: no hook object, no retained extension-classloader
     * class in the JVM's shutdown-hook table.
     */
    @Test
    fun theShutdownHookIsRegisteredLazilyOnTheFirstTempFile() {
        assertFalse(
            CliTempFileRegistry.isHookRegisteredForTests(),
            "No hook may exist before the first register(...). Registering eagerly would make every " +
                "Burp session pay for a CLI backend it may never use, and would put an " +
                "extension-classloader object into the JVM's shutdown-hook table at load time (D-03).",
        )

        CliTempFileRegistry.register(newFile("first.txt"))
        assertTrue(
            CliTempFileRegistry.isHookRegisteredForTests(),
            "The first temp file must arm the hook — otherwise a clean Burp quit mid-call leaks the " +
                "file, which is the one case the net exists for.",
        )

        CliTempFileRegistry.register(newFile("second.txt"))
        assertTrue(
            CliTempFileRegistry.isHookRegisteredForTests(),
            "A second registration must reuse the same hook. Registering once per call would rebuild " +
                "the accumulation defect in a coarser form (threat T-24-07).",
        )

        CliTempFileRegistry.shutdown()
        assertFalse(
            CliTempFileRegistry.isHookRegisteredForTests(),
            "shutdown() must leave no hook behind: an unremoved hook is an extension-classloader " +
                "object and pins a dead classloader across extension reloads (D-03, threat T-24-07).",
        )

        CliTempFileRegistry.shutdown()
        assertFalse(
            CliTempFileRegistry.isHookRegisteredForTests(),
            "shutdown() must be idempotent — App.shutdown() can run more than once across a reload.",
        )
    }

    // -------- REL-07-F: the structural gates (D-01, D-03) --------

    /**
     * REL-07-F (SC5) — the structural gate that pins the swap in `CliBackend.kt`, and the genuinely
     * red-before-green half of this plan: the seven behavioural tests above drive a class that did not
     * exist, so they were red merely by non-compilation, whereas this one reads the real pre-fix source
     * and fails against it.
     *
     * **Comment lines are stripped, block comments included.** That strip is what lets
     * `CliTempFileRegistry.kt` name the removed JDK facility in its own KDoc — which D-04 requires —
     * without invalidating this gate. `build.gradle.kts` declares the whole `src/main/kotlin` tree as a
     * `tasks.test` input under the property name `mainSourceTreeStructuralInputs`, so an edit to
     * `CliBackend.kt` re-runs this assertion instead of serving it from cache.
     */
    @Test
    fun theCliBackendTempFilesCannotRegressToPerInvocationJvmRegistration() {
        val code = codeLinesOf(CLI_BACKEND_SOURCE)
        // Assembled from parts so the token this test forbids is never itself a literal that a careless
        // future grep over the test tree could mistake for a real use.
        val forbiddenRegistration = "delete" + "OnExit("

        assertEquals(
            0,
            code.count { it.contains(forbiddenRegistration) },
            "CliBackend ledger: the temp-file sites must not go back to the JVM's own exit-time deletion " +
                "facility. It keeps its registrations in a static set with NO removal API, so each call " +
                "restores one permanent, unremovable JVM shutdown-hook entry that is retained for the life " +
                "of the Burp JVM — growth bounded by lifetime invocation count (REL-07 / SC5, D-01, " +
                "threat T-24-15).",
        )
        assertEquals(
            2,
            code.count { it.contains("CliTempFileRegistry.register(") },
            "CliBackend ledger: exactly two registration sites — the codex output file and the " +
                "large-prompt file. Fewer means a temp file lost its safety net for a clean Burp quit " +
                "mid-call; more means a third temp file appeared that this suite does not cover.",
        )
        assertEquals(
            3,
            code.count { it.contains("CliTempFileRegistry.deleteAndDeregister(") },
            "CliBackend ledger: exactly three cleanup sites. Two are in the finally block, one per temp " +
                "file. The third is in the prompt write-failure branch, which returns before the outer " +
                "finally and is therefore the ONLY place that can clear its own entry — dropping it " +
                "retains one entry per failed write for the life of the JVM, which is the very growth " +
                "D-01 removes.",
        )
        assertEquals(
            0,
            code.count { it.contains("CliTempFileRegistry.deregister(") },
            "CliBackend ledger: the backend must NEVER deregister on its own. An unconditional " +
                "`delete()` then `deregister()` pair abandons every file whose delete returned false — " +
                "and `File.delete()` reports failure by RETURNING FALSE, not by throwing, which is what " +
                "happens on Windows while the CLI child still holds the handle. The entry is dropped, so " +
                "neither the exit hook nor App.shutdown()'s drain can ever sweep the file, and a " +
                "burp_uv_prompt_ file holding the full prompt is left in the shared OS temp directory " +
                "on the one platform where owner-only permissions are also skipped. Route every site " +
                "through CliTempFileRegistry.deleteAndDeregister(...), which deregisters only once the " +
                "file is actually gone.",
        )
    }

    /**
     * D-03 — the unload half of SC5, pinned structurally.
     *
     * The JVM exit hook does NOT fire when the extension is unloaded while Burp keeps running, so
     * `App.shutdown()`'s drain is the only thing that covers a CLI call in flight at unload, and the
     * only thing that stops a reload from accumulating hooks that pin a dead classloader (threat
     * T-24-07).
     */
    @Test
    fun appShutdownDrainsTheRegistryAfterTheBackendRegistryAndBeforeTheWorkerPool() {
        val code = codeLinesOf(APP_SOURCE)

        assertEquals(
            1,
            code.count { it.contains("safeShutdownStep(\"CLI temp files\")") },
            "App ledger: exactly one \"CLI temp files\" shutdown step. Zero means an extension unload " +
                "leaves the extension's own exit hook armed — an extension-classloader object pinning a " +
                "dead classloader on every reload — and leaves any CLI call in flight at unload without " +
                "any cleanup at all, because the JVM exit hook does not fire on unload (D-03).",
        )
        assertEquals(
            1,
            code.count { it.contains("CliTempFileRegistry.shutdown()") },
            "App ledger: the step must actually call into the registry. One call site, no more.",
        )

        val backendRegistryStep = code.indexOfFirst { it.contains("safeShutdownStep(\"Backend registry\")") }
        val cliTempFilesStep = code.indexOfFirst { it.contains("safeShutdownStep(\"CLI temp files\")") }
        val workerPoolStep = code.indexOfFirst { it.contains("safeShutdownStep(\"Worker pool\")") }

        assertTrue(
            backendRegistryStep >= 0 && workerPoolStep >= 0,
            "App ledger: both neighbouring steps must still exist, or this ordering assertion is vacuous. " +
                "Found Backend registry at $backendRegistryStep and Worker pool at $workerPoolStep.",
        )
        assertTrue(
            cliTempFilesStep > backendRegistryStep,
            "App ledger: the drain must run AFTER the backend registry has shut down. The CLI executor " +
                "lives under the backend registry, so draining earlier would sweep a set that is still " +
                "moving — a call whose finally block has not run yet would have its temp files deleted " +
                "out from under it.",
        )
        assertTrue(
            cliTempFilesStep < workerPoolStep,
            "App ledger: the drain must run BEFORE the worker pool is torn down, so the step order stays " +
                "the one D-03 fixed and reviewed.",
        )
    }

    // ---------------------------------------------------------------------------------------------
    // Fixture
    // ---------------------------------------------------------------------------------------------

    /**
     * The non-comment lines of [path], read from disk.
     *
     * Named, resolved and asserted rather than left to surface as a bare `FileNotFoundException`,
     * which is what a build-layout change would otherwise produce here. A line counts as a comment
     * when its first non-space characters are a line-comment marker, a continuation asterisk, or a
     * block-comment opener; stripping BLOCK comments is what makes it safe for the counted tokens to
     * be named in the prose that documents them. (The three markers are written out longhand rather
     * than quoted, because Kotlin block comments nest — a literal opener inside this KDoc would open a
     * nested comment and swallow the rest of the file.)
     */
    private fun codeLinesOf(path: String): List<String> {
        // SourceRoots.file fails naming both production roots when the file is in neither or in both, so
        // a whole-file move between src/main and src/full keeps this guard reading the real file.
        val file = SourceRoots.file(path)
        return file
            .readLines()
            .filterNot { line ->
                val trimmed = line.trimStart()
                trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
            }
    }

    private companion object {
        const val SIMULATED_CALL_COUNT = 10
        const val CLI_BACKEND_SOURCE = "com/six2dez/burp/aiagent/backends/cli/CliBackend.kt"
        const val APP_SOURCE = "com/six2dez/burp/aiagent/App.kt"
    }
}
