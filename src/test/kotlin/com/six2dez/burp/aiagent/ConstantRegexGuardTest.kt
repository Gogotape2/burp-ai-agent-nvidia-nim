package com.six2dez.burp.aiagent

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Phase 34 / D-09, PERF-01 — a regex built from a string literal is compiled once: as a top-level
 * property, an `object` property or a `companion object` property, never inside a function, a lambda, a
 * getter or a class body.
 *
 * Round 4 of the BApp Store review cited regexes compiled on hot paths. Phase 34 hoisted every constant
 * pattern in both production roots (verbatim, D-10); this guard keeps them hoisted. A construction is
 * `Regex(..)`, `kotlin.text.Regex(..)`, `"..".toRegex(..)` or `Pattern.compile(..)` on a code line (a line
 * whose first non-space characters open a line comment, continue a KDoc or open a block comment is
 * skipped). The guard reads source text, with no Kotlin parser, in three steps:
 *  1. find each construction token on a code line;
 *  2. keep it only if its pattern argument (or, for `.toRegex`, its receiver) is ONE string literal: a
 *     normal or raw string, with an optional `pattern =` / `regex =` name, closed and followed by `,` or
 *     `)`, and with no `$name` / `${..}` interpolation. A construction whose argument is not a literal
 *     (a variable, a concatenation, an interpolated string) is dynamic by definition (D-09): data-derived
 *     patterns (STRICT host anonymisation, response-derived tokens, MCP caller patterns, user redaction
 *     patterns) stay built at run time and uncached in shared state (D-08), so they are never reported;
 *  3. walk the enclosing declarations by indentation (ktlint keeps it canonical, and `ktlintCheck` runs in
 *     `check`): from the site line upwards, every earlier code line with smaller indentation that opens a
 *     declaration joins the chain, the site line first when it is a declaration itself. The literal is
 *     allowed iff the innermost declaration is a `val` / `var` without a `get()` on its line AND it is a
 *     top-level property (a one-element chain at indentation 0) or the next declaration out is an `object`
 *     or a `companion object`.
 *
 * Known limitation: a literal regex inside a DEFERRED lambda of a top-level property initializer (an MCP
 * handler lambda, say) passes, because its innermost declaration is the top-level property. None exists
 * today: the five handler sites in GenericHistoryTools and GenericSiteMapTools build from `input.regex`.
 * The allowlist is keyed by `<package-relative path>|<literal>` so an entry survives a move between
 * `src/main` and `src/full` and a line shift, and it is asserted empty.
 */
class ConstantRegexGuardTest {
    @Test
    fun noLiteralRegexIsBuiltOutsideAConstant() {
        val files = SourceRoots.kotlinFiles()
        SourceRoots.PRODUCTION.forEach { name ->
            val root = SourceRoots.root(name).canonicalFile.toPath()
            assertTrue(
                files.any { it.canonicalFile.toPath().startsWith(root) },
                "the walk saw no Kotlin file under `$name`, so this guard would pass over it without reading it",
            )
        }

        val hits =
            files.flatMap { file ->
                val packagePath = SourceRoots.packageRelativePath(file)
                findLocalLiteralRegexes(SourceRoots.relativePath(file), file.readLines())
                    .filterNot { "$packagePath|${it.literal}" in ALLOWLIST }
            }

        assertTrue(
            hits.isEmpty(),
            "A regex is built from a string literal outside a constant (Phase 34 / D-09, PERF-01), so it is " +
                "compiled per call or per instance. Move it, verbatim, to a top-level `private val`, an " +
                "`object` property or a `companion object` property.\n" +
                hits.joinToString("\n") { "  ${it.location} -> ${it.line.trim()}" },
        )
    }

    @Test
    fun theAllowListIsEmpty() {
        // Every Phase 34 site was hoisted rather than exempted; an entry here is a reviewed change to this test.
        assertEquals(emptyMap<String, String>(), ALLOWLIST)
    }

    @Test
    fun eachShapeOfALocalLiteralRegexIsReported() {
        // Fail-first proof: if the finder or the placement walk stopped seeing one of these shapes, the
        // whole-tree guard above would pass over a tree that compiles that kind of regex per call again.
        val q3 = "\"\"\""
        val cases: List<Pair<String, List<String>>> =
            listOf(
                "expression-body function" to listOf("package x", "fun f() = Regex(\"a\")"),
                "local val with an option" to
                    listOf("package x", "fun f() {", "    val r = Regex(\"a\", RegexOption.IGNORE_CASE)", "}"),
                "multi-line call in a function" to
                    listOf("package x", "fun f() {", "    val r =", "        Regex(", "            \"a\",", "        )", "}"),
                "toRegex on a literal" to listOf("package x", "fun f() {", "    val r = \"a\".toRegex()", "}"),
                "Pattern.compile" to listOf("package x", "fun f() {", "    val p = Pattern.compile(\"a\")", "}"),
                "named pattern argument" to listOf("package x", "fun f() {", "    val r = Regex(pattern = \"a\")", "}"),
                "raw string" to listOf("package x", "fun f() {", "    val r = Regex(${q3}a$q3)", "}"),
                "four-quote raw string" to listOf("package x", "fun f() {", "    val r = Regex(\"${q3}a$q3\")", "}"),
                "escaped dollar is still a literal" to
                    listOf("package x", "fun f() {", "    val r = Regex(\"\\\\\\\$where\")", "}"),
                "property in a class body" to listOf("package x", "class C {", "    private val r = Regex(\"a\")", "}"),
                "top-level getter" to listOf("package x", "val r: Regex", "    get() = Regex(\"a\")"),
                "inside a string template" to
                    listOf("package x", "fun f(x: String) {", "    val s = \"\${x.replace(Regex(\"a\"), \"\")}\"", "}"),
            )
        cases.forEach { (shape, lines) ->
            val hits = findLocalLiteralRegexes("synthetic/Fixture.kt", lines)
            assertEquals(1, hits.size, "the guard must report exactly one hit for the $shape shape: $lines -> $hits")
        }
    }

    @Test
    fun allowedAndDynamicConstructionsAreNotReported() {
        val q3 = "\"\"\""
        val lines =
            listOf(
                "package x",
                "private val R = Regex(\"a\")",
                "private val MULTI =",
                "    Regex(",
                "        \"a\",",
                "        RegexOption.IGNORE_CASE,",
                "    )",
                "object O {",
                "    private val R = Regex(${q3}a$q3)",
                "    val P = Pattern.compile(\"a\")",
                "}",
                "class C {",
                "    private companion object {",
                "        val R = Regex(\"a\")",
                "    }",
                "}",
                "fun f(dynamic: String, x: String) {",
                "    val a = Regex(dynamic)",
                "    val b = Regex(\"a\$x\")",
                "    val c = Regex(\"a\${x.length}\")",
                "    val d = Regex(\"a\" + B)",
                "    val e = Regex.escape(x)",
                "    val g = GetSiteMapRegex(x)",
                "    // val r = Regex(\"a\")",
                "    /* Regex(\"a\") */",
                "     * Regex(\"a\") in a KDoc line",
                "}",
            )
        assertEquals(
            emptyList<String>(),
            findLocalLiteralRegexes("synthetic/Fixture.kt", lines).map { "${it.location} -> ${it.line.trim()}" },
            "constant-level, dynamic and commented constructions must not be reported",
        )
    }

    private data class Hit(
        val location: String,
        val literal: String,
        val line: String,
    )

    private data class Literal(
        val body: String,
        val end: Int,
        val raw: Boolean,
    )

    private data class Declaration(
        val kind: String,
        val indent: Int,
        val line: String,
    )

    /** Every literal-built regex on a code line of [lines] that is not at constant level, as `path:line`. */
    private fun findLocalLiteralRegexes(
        relativePath: String,
        lines: List<String>,
    ): List<Hit> =
        lines.indices.filterNot { lines[it].isCommentLine() }.flatMap { index ->
            CONSTRUCTION
                .findAll(lines[index])
                .mapNotNull { match -> literalArgument(lines, index, match) }
                .filterNot { isConstantLevel(lines, index) }
                .map { literal -> Hit("$relativePath:${index + 1}", literal.body, lines[index]) }
                .toList()
        }

    /**
     * Step 2: the single, non-interpolated string literal [match] compiles, or null when the pattern is
     * dynamic. `.toRegex` reads its receiver; the other tokens read the argument after the parenthesis,
     * across the next lines so a multi-line call or raw string is seen whole.
     */
    private fun literalArgument(
        lines: List<String>,
        index: Int,
        match: MatchResult,
    ): Literal? {
        val line = lines[index]
        if (match.value.startsWith(".")) {
            val receiver = literalsIn(line.substring(0, match.range.first)).lastOrNull()
            return receiver?.takeIf { it.end == match.range.first && !it.interpolates() }
        }
        val following = lines.subList(index + 1, minOf(lines.size, index + 1 + LOOKAHEAD_LINES)).map { it.trimStart() }
        val text = (listOf(line.substring(match.range.last + 1)) + following).joinToString("\n").trimStart()
        val argument = text.replaceFirst(NAMED_ARGUMENT, "")
        val literal = literalAt(argument, 0) ?: return null
        val next = argument.substring(literal.end).trimStart().firstOrNull()
        return literal.takeIf { (next == ',' || next == ')') && !it.interpolates() }
    }

    /**
     * The string literal that opens at [start] of [text] (a raw string or a normal string), or null when
     * none opens there or it does not close. A raw string closes at the last quote of its closing run,
     * so `""""a""""` has body `"a"`; a normal string honours backslash escapes, skips `${..}` templates
     * and cannot span a line.
     */
    private fun literalAt(
        text: String,
        start: Int,
    ): Literal? {
        if (text.startsWith(RAW_QUOTE, start)) {
            val close = text.indexOf(RAW_QUOTE, start + RAW_QUOTE.length)
            if (close < 0) return null
            var end = close + RAW_QUOTE.length
            while (end < text.length && text[end] == '"') end++
            return Literal(text.substring(start + RAW_QUOTE.length, end - RAW_QUOTE.length), end, raw = true)
        }
        if (start >= text.length || text[start] != '"') return null
        var i = start + 1
        while (i < text.length) {
            when {
                text[i] == '\\' -> i += 2
                text.startsWith("\${", i) -> i = skipTemplate(text, i + 2)
                text[i] == '"' -> return Literal(text.substring(start + 1, i), i + 1, raw = false)
                text[i] == '\n' -> return null
                else -> i++
            }
        }
        return null
    }

    /** The index after the `}` that closes a template whose body starts at [bodyStart]. */
    private fun skipTemplate(
        text: String,
        bodyStart: Int,
    ): Int {
        var depth = 1
        var i = bodyStart
        while (i < text.length && depth > 0) {
            when (text[i]) {
                '{' -> depth++
                '}' -> depth--
                '\n' -> return text.length
            }
            i++
        }
        return i
    }

    /** Every string literal on one line of code, left to right; char literals are skipped and a line comment ends the scan. */
    private fun literalsIn(code: String): List<Literal> {
        val found = mutableListOf<Literal>()
        var i = 0
        while (i < code.length) {
            when {
                code.startsWith("//", i) -> return found
                code[i] == '\'' -> i = (code.indexOf('\'', i + if (code.startsWith("'\\", i)) 3 else 2) + 1).takeIf { it > 0 } ?: return found
                code[i] == '"' -> {
                    val literal = literalAt(code, i) ?: return found
                    found += literal
                    i = literal.end
                }
                else -> i++
            }
        }
        return found
    }

    /** True when the body reads a template: `$` + a name or `{`, unescaped (raw strings have no escapes). */
    private fun Literal.interpolates(): Boolean =
        body.indices.any { i ->
            body[i] == '$' &&
                i + 1 < body.length &&
                (body[i + 1].isLetter() || body[i + 1] == '_' || body[i + 1] == '{') &&
                (raw || precedingBackslashes(body, i) % 2 == 0)
        }

    private fun precedingBackslashes(
        text: String,
        index: Int,
    ): Int {
        var count = 0
        while (index - count - 1 >= 0 && text[index - count - 1] == '\\') count++
        return count
    }

    /** Step 3: the enclosing-declaration chain of line [index] places it at top level, in an object or in a companion. */
    private fun isConstantLevel(
        lines: List<String>,
        index: Int,
    ): Boolean {
        val chain = declarationChain(lines, index)
        val innermost = chain.firstOrNull() ?: return false
        if (innermost.kind != "val" && innermost.kind != "var") return false
        if (GETTER.containsMatchIn(innermost.line)) return false
        val topLevel = chain.size == 1 && innermost.indent == 0
        return topLevel || chain.getOrNull(1)?.kind in CONSTANT_HOLDERS
    }

    /** Innermost first: the site line when it declares, then each earlier code line with smaller indentation that declares. */
    private fun declarationChain(
        lines: List<String>,
        index: Int,
    ): List<Declaration> {
        val chain = mutableListOf<Declaration>()
        declarationOf(lines[index])?.let { chain += it }
        var indent = lines[index].indentation()
        for (j in index - 1 downTo 0) {
            if (indent == 0) break
            val line = lines[j]
            if (line.isBlank() || line.isCommentLine() || line.indentation() >= indent) continue
            val declaration = declarationOf(line) ?: continue
            chain += declaration
            indent = declaration.indent
        }
        return chain
    }

    private fun declarationOf(line: String): Declaration? =
        DECLARATION.find(line)?.let { match ->
            Declaration(match.groupValues[1].replace(WHITESPACE, " "), line.indentation(), line)
        }

    private fun String.indentation(): Int = length - trimStart().length

    /** A line comment, a KDoc continuation or a block-comment opener (the three markers spelled out in the class KDoc). */
    private fun String.isCommentLine(): Boolean {
        val trimmed = trimStart()
        return trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")
    }

    private companion object {
        /** `<package-relative path>|<literal body>` to the reason it may compile per call. Empty since Phase 34. */
        val ALLOWLIST: Map<String, String> = emptyMap()

        /** Lines read after the token; only a raw string needs more than one, and none in the tree is longer. */
        const val LOOKAHEAD_LINES = 30
        const val RAW_QUOTE = "\"\"\""

        val CONSTANT_HOLDERS = setOf("object", "companion object")

        /** RESEARCH Pattern 6 step 1, plus the fully qualified `kotlin.text.Regex(` the lookbehind would skip. */
        val CONSTRUCTION =
            Regex("""(?<![A-Za-z0-9_.])Regex\s*\(|\bkotlin\.text\.Regex\s*\(|\.toRegex\s*\(|\bPattern\s*\.\s*compile\s*\(""")

        val NAMED_ARGUMENT = Regex("""^(?:pattern|regex)\s*=\s*""")
        val GETTER = Regex("""\bget\s*\(\s*\)""")
        val WHITESPACE = Regex("""\s+""")

        /** RESEARCH Pattern 6 step 3: annotations and modifiers, then the declaration keyword (group 1). */
        val DECLARATION =
            Regex(
                """^\s*(?:@[\w.]+(?:\([^)]*\))?\s+)*""" +
                    """(?:(?:private|internal|public|protected|override|inline|suspend|const|lateinit|data|sealed|""" +
                    """abstract|open|operator|infix|tailrec|enum|inner|value|annotation)\s+)*""" +
                    """(fun|val|var|object|class|interface|companion\s+object|init|get(?=\s*\())\b""",
            )
    }
}
