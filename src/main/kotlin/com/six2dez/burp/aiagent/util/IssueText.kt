package com.six2dez.burp.aiagent.util

object IssueText {
    private val fencedCodeRegex = Regex("(?s)```[a-zA-Z0-9_-]*\\n(.*?)```")
    private val markdownLinkRegex = Regex("\\[([^\\]]+)]\\(([^)]+)\\)")
    private val headingRegex = Regex("(?m)^#{1,6}\\s+")
    private val blockquoteRegex = Regex("(?m)^>\\s?")

    /**
     * A whole run of underscores that is NOT enclosed by a letter or digit on both sides. The first
     * alternative is a run with no letter, digit or underscore before it; the second is a run with
     * no underscore before it and no letter, digit or underscore after it. Both lookarounds sit on
     * the run's ends, so the inner underscores of `a__b` never match on their own.
     */
    private val emphasisUnderscoreRegex =
        Regex("(?<![\\p{L}\\p{N}_])_+|(?<!_)_+(?![\\p{L}\\p{N}_])")

    /**
     * Removes Markdown markers so Burp shows the text as plain text.
     *
     * An underscore between two letters or digits is kept: names such as `access_token` and
     * `session_id` are what read-time privacy redaction keys on, and dropping the underscore hid
     * them from it (32-REVIEW CR-01 gap closure). An emphasis underscore at a word edge
     * (`_italic_`, `__bold__`) is still removed, as is every asterisk.
     */
    fun sanitize(input: String): String {
        if (input.isBlank()) return input
        var text = input.replace("\r\n", "\n").replace("\r", "\n")

        // Remove fenced code blocks but keep their content.
        text =
            text.replace(fencedCodeRegex) { m ->
                m.groupValues[1]
            }

        // Inline code/backticks.
        text = text.replace("`", "")

        // Markdown links: [text](url) -> text (url)
        text = text.replace(markdownLinkRegex, "$1 ($2)")

        // Headings and blockquotes.
        text = text.replace(headingRegex, "")
        text = text.replace(blockquoteRegex, "")

        // Bold/italic markers. Underscores inside a word are kept (see the KDoc above).
        text =
            text
                .replace("**", "")
                .replace("*", "")
                .replace(emphasisUnderscoreRegex, "")

        return text.trim()
    }
}
