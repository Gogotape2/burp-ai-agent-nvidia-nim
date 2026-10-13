package com.six2dez.burp.aiagent.mcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

/** Core issue-name guards; generic helpers are covered by FullMcpToolHelpersTest. */
class McpToolHelpersTest {
    @Nested
    inner class WithAiIssuePrefix {
        @Test
        fun anUnprefixedNameGainsThePrefix() {
            assertEquals("[AI] SQL injection", withAiIssuePrefix("SQL injection"))
        }

        @Test
        fun aNameAlreadyCarryingEitherRecognisedPrefixIsReturnedUnchanged() {
            assertEquals("[AI] SQL injection", withAiIssuePrefix("[AI] SQL injection"))
            assertEquals("[AI Passive] SQL injection", withAiIssuePrefix("[AI Passive] SQL injection"))
        }

        @Test
        fun prefixRecognitionIsCaseInsensitive() {
            assertEquals("[ai] SQL injection", withAiIssuePrefix("[ai] SQL injection"))
            assertEquals("[AI PASSIVE] SQL injection", withAiIssuePrefix("[AI PASSIVE] SQL injection"))
        }

        @Test
        fun surroundingWhitespaceIsTrimmedOnBothBranches() {
            assertEquals("[AI] SQL injection", withAiIssuePrefix("   SQL injection   "))
            assertEquals("[AI] SQL injection", withAiIssuePrefix("  [AI] SQL injection  "))
        }
    }
}
