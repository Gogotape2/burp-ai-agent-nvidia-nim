package com.six2dez.burp.aiagent.mcp

import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.lang.reflect.Modifier

private const val GATE_FILE = "com/six2dez/burp/aiagent/mcp/ToolApprovalGate.kt"

/** The object-private factory that mints the model origin. Named once so both channels below agree. */
private const val FACTORY = "approvedOrigin"

/** The file-private class the factory returns as [ToolCallOrigin], never as itself. */
private const val MODEL_ORIGIN_CLASS = "ModelApproved"

/**
 * Every declaration site of [FACTORY] in the gate file, whatever its visibility keyword.
 *
 * Matching the *declaration* rather than the string is what keeps the assertions non-vacuous: a test
 * that only searched for `private fun approvedOrigin` would pass silently if the function were renamed,
 * and a test that only searched for `internal fun approvedOrigin` would pass if it were deleted.
 */
private val factoryDeclarationRegex = Regex("""^\s*(?:(internal|public|private|protected)\s+)?fun\s+$FACTORY\s*\(""", RegexOption.MULTILINE)

/** Same idea for the file-private class: find the declaration, then judge the keyword in front of it. */
private val modelOriginDeclarationRegex = Regex("""^\s*(?:(internal|public|private|protected)\s+)?class\s+$MODEL_ORIGIN_CLASS\s*\(""", RegexOption.MULTILINE)

/**
 * SC5 / CR-02 regression guard: the model origin can only be minted from inside [ToolApprovalGate].
 *
 * **Why this test exists, stated plainly.** CR-02 found `approvedOrigin` shipped as `internal`, which
 * in Kotlin is MODULE-wide — any file in the main source set could write
 * `ToolApprovalGate.approvedOrigin(SecTier.AUTO, ToolDecision.AUTO)` and hand the result straight to
 * `McpToolExecutor.executeTool` with no card, no session-memory consultation and no audit record. A
 * module-wide factory for a file-private type is simply a module-wide factory. It was narrowed to
 * `private`, and the compiler does enforce the current state — but **widening it back compiles cleanly
 * and, until this file existed, failed nothing.** Phase 22's verification recorded that as WARN-6, and
 * its reasoning is the reason this is not deferred: the control had already regressed once, silently,
 * while ADR-15 asserted the property anyway. The other three code-review fixes each shipped with a
 * regression test; this is the fourth.
 *
 * **Two independent channels, because neither alone is sufficient.**
 *
 * 1. *Source text.* The only option for [MODEL_ORIGIN_CLASS]: Kotlin has no file-private JVM
 *    visibility, so a top-level `private class` and an `internal` one are not reliably distinguishable
 *    after compilation in a way worth asserting on. Reading the declaration is what the property
 *    actually says. The pattern — read a repo file from disk, assert on its text — is
 *    `DecisionsAdrTest`'s, and so is the obligation that comes with it: **`GATE_FILE` is declared as a
 *    `tasks.test` input in `build.gradle.kts`.** Without that declaration Gradle cannot infer a file
 *    read at runtime, a comment-only edit produces byte-identical compiled output and therefore an
 *    identical cache key, and the test task is restored from cache with the guard never running — the
 *    exact defect plan 22-09 found and fixed for `DecisionsAdrTest`.
 * 2. *Bytecode.* For [FACTORY] the compiler's own output can be checked, and it is the stronger
 *    statement: not "the source says private" but "the compiler emitted a private method". Kotlin
 *    mangles an `internal` member's name with the module name, so widening changes both the modifier
 *    and the emitted name — this assertion sees either.
 *
 * A source-text guard is a weak instrument in general. It is the right one here because the property
 * being pinned IS a visibility keyword, and because the alternative on offer is no guard at all.
 */
class ToolApprovalGateVisibilityTest {
    @Test
    fun theModelOriginFactoryIsDeclaredPrivateInSource() {
        val declarations = factoryDeclarationRegex.findAll(gateSource()).toList()

        assertEquals(
            1,
            declarations.size,
            "Expected exactly one `fun $FACTORY(` declaration in $GATE_FILE, found ${declarations.size}. " +
                "If it was renamed or split, point this guard at the new name rather than deleting it — " +
                "SC5's whole mechanism is that the model origin has ONE minting site.",
        )
        assertEquals(
            "private",
            declarations.single().groupValues[1],
            "`$FACTORY` in $GATE_FILE is no longer `private`. Kotlin's `internal` is MODULE-wide, so any " +
                "file in the main source set could then mint a model-approved origin and reach " +
                "McpToolExecutor.executeTool with no approval card and no audit record — which is exactly " +
                "what CR-02 found shipped. Do not widen this to let a test reach it: a test that needs a " +
                "model origin should obtain one the way production does, from evaluate() or resolve().",
        )
    }

    @Test
    fun theModelOriginFactoryIsPrivateInTheCompiledObject() {
        // The same property as above, read from what the compiler actually emitted rather than from what
        // the source says — so a reformat cannot satisfy it and a comment cannot break it.
        val candidates =
            ToolApprovalGate::class.java.declaredMethods
                .filter { it.name.startsWith(FACTORY) }

        assertEquals(
            1,
            candidates.size,
            "Expected exactly one compiled method named $FACTORY* on ToolApprovalGate, found " +
                candidates.joinToString { it.name },
        )
        val method = candidates.single()
        // An `internal` member is emitted as `approvedOrigin$<module>`, so the unmangled name is itself
        // evidence of the visibility. Asserting both catches a widening whichever way it shows up first.
        assertEquals(
            FACTORY,
            method.name,
            "The compiled method name is mangled, which is how Kotlin emits an `internal` member. " +
                "`$FACTORY` must stay `private` to the ToolApprovalGate object (CR-02).",
        )
        assertTrue(
            Modifier.isPrivate(method.modifiers),
            "The compiler emitted `$FACTORY` as non-private, so any file in the main source set can mint " +
                "a model-approved origin. That is CR-02 regressed.",
        )
    }

    @Test
    fun theModelApprovedOriginClassIsFilePrivate() {
        val declarations = modelOriginDeclarationRegex.findAll(gateSource()).toList()

        assertEquals(
            1,
            declarations.size,
            "Expected exactly one `class $MODEL_ORIGIN_CLASS(` declaration in $GATE_FILE, found " +
                "${declarations.size}.",
        )
        assertEquals(
            "private",
            declarations.single().groupValues[1],
            "`$MODEL_ORIGIN_CLASS` in $GATE_FILE is no longer top-level `private`, which in Kotlin means " +
                "FILE-private. That is the other half of the SC5 mechanism: no other file may construct " +
                "the model origin or even name its type. `internal` does NOT work here — it is " +
                "module-wide, so every file in the main source set could mint one. Do not move this " +
                "class to its own file either; the seal is file-scoped, and splitting the file " +
                "downgrades the control to a comment (see the header of $GATE_FILE).",
        )
    }

    /**
     * Reads the gate source from whichever production root holds it.
     *
     * [SourceRoots.file] fails naming both roots when the file is in neither or in both, rather than
     * letting a future build-layout change surface as an unhelpful empty string that passes every
     * `contains`. If it fails, fix the path rather than deleting this test — it is the only automated
     * check that SC5's minting boundary is still narrow.
     */
    private fun gateSource(): String = SourceRoots.file(GATE_FILE).readText()
}
