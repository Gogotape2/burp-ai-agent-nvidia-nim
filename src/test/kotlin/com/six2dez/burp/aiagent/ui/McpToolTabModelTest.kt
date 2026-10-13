package com.six2dez.burp.aiagent.ui

import com.six2dez.burp.aiagent.mcp.McpToolDescriptor
import com.six2dez.burp.aiagent.mcp.SecTier
import com.six2dez.burp.aiagent.ui.design.BadgeStyle
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for [McpToolTabModel] — pure grouping/badge/filter/bulk-toggle helpers.
 *
 * No Swing instantiation. No javax.swing or java.awt imports.
 * All 14+ tests exercise observable behaviour defined in the UI-SPEC.
 */
class McpToolTabModelTest {
    // -------------------------------------------------------------------------
    // Test helper — builds a McpToolDescriptor with minimal repetition
    // -------------------------------------------------------------------------

    private fun descriptor(
        id: String,
        title: String,
        description: String = "",
        category: String = "Cat",
        proOnly: Boolean = false,
        unsafeOnly: Boolean = false,
        // Defaulted at the HELPER level only. D-03 is about the production `data class`
        // McpToolDescriptor, where secTier has deliberately no default so a new catalog tool that
        // forgets to classify itself does not compile. Defaulting it in a test convenience does not
        // weaken that: these fixtures are not catalog entries, and the existing call sites below
        // exercise grouping/badge/filter behaviour that is independent of the tier.
        secTier: SecTier = SecTier.CONFIRM,
    ) = McpToolDescriptor(
        id = id,
        title = title,
        description = description,
        category = category,
        defaultEnabled = true,
        proOnly = proOnly,
        unsafeOnly = unsafeOnly,
        secTier = secTier,
    )

    // -------------------------------------------------------------------------
    // groupTools — provenance comes from the registry's core id set (D-14, BUILD-04)
    // -------------------------------------------------------------------------

    @Test
    fun groupTools_coreIdsGoToCoreListAndTheRestToProvided() {
        val tools =
            listOf(
                descriptor("n1", "Native One"),
                descriptor("n2", "Native Two"),
                descriptor("g1", "Generic One"),
                descriptor("g2", "Generic Two"),
            )
        val grouping = McpToolTabModel.groupTools(tools, coreIds = setOf("n1", "n2"))

        assertEquals(listOf("n1", "n2"), grouping.core.map { it.id })
        assertEquals(listOf("g1", "g2"), grouping.provided.map { it.id })
    }

    @Test
    fun groupTools_coreListIsSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zebra"),
                descriptor("a", "Alpha"),
                descriptor("m", "Mango"),
            )
        val grouping = McpToolTabModel.groupTools(tools, coreIds = setOf("z", "a", "m"))

        assertEquals(listOf("Alpha", "Mango", "Zebra"), grouping.core.map { it.title })
        assertTrue(grouping.provided.isEmpty())
    }

    @Test
    fun groupTools_providedListIsSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zebra"),
                descriptor("a", "Alpha"),
                descriptor("m", "Mango"),
            )
        val grouping = McpToolTabModel.groupTools(tools, coreIds = emptySet())

        assertEquals(listOf("Alpha", "Mango", "Zebra"), grouping.provided.map { it.title })
        assertTrue(grouping.core.isEmpty())
    }

    @Test
    fun groupTools_aCoreIdWithNoMatchingToolIsIgnored() {
        val tools = listOf(descriptor("g1", "Generic One"))
        val grouping = McpToolTabModel.groupTools(tools, coreIds = setOf("absent"))

        assertTrue(grouping.core.isEmpty())
        assertEquals(listOf("g1"), grouping.provided.map { it.id })
    }

    // -------------------------------------------------------------------------
    // badgeStyle — UI-04, keyed on the core id set
    // -------------------------------------------------------------------------

    @Test
    fun badgeStyle_coreToolReturnsBadgeNative() {
        val tool = descriptor("t1", "Tool")
        assertEquals(BadgeStyle.NATIVE, McpToolTabModel.badgeStyle(tool, coreIds = setOf("t1")))
    }

    @Test
    fun badgeStyle_providedToolReturnsBadgeFull() {
        val tool = descriptor("t1", "Tool")
        assertEquals(BadgeStyle.FULL, McpToolTabModel.badgeStyle(tool, coreIds = setOf("other")))
    }

    // -------------------------------------------------------------------------
    // filterPredicate — UI-05 search
    // -------------------------------------------------------------------------

    @Test
    fun filterPredicate_blankQueryMatchesAll() {
        val tool = descriptor("t1", "Some Tool", description = "Does something")

        // Empty string
        assertTrue(McpToolTabModel.filterPredicate("", tool))
        // Whitespace-only
        assertTrue(McpToolTabModel.filterPredicate("   ", tool))
    }

    @Test
    fun filterPredicate_titleMatchCaseInsensitive() {
        val tool = descriptor("t1", "AI Analyze", description = "Sends text to AI backend")

        assertTrue(McpToolTabModel.filterPredicate("analyze", tool))
        assertTrue(McpToolTabModel.filterPredicate("ANALYZE", tool))
        assertTrue(McpToolTabModel.filterPredicate("Analyze", tool))
    }

    @Test
    fun filterPredicate_descriptionMatchCaseInsensitive() {
        val tool = descriptor("t1", "Proxy History", description = "Displays proxy history items")

        assertTrue(McpToolTabModel.filterPredicate("PROXY", tool))
        assertTrue(McpToolTabModel.filterPredicate("proxy", tool))
        assertTrue(McpToolTabModel.filterPredicate("history items", tool))
    }

    @Test
    fun filterPredicate_nonMatchReturnsFalse() {
        val tool = descriptor("t1", "URL Encode", description = "URL encodes the input string")

        assertFalse(McpToolTabModel.filterPredicate("xyzzy", tool))
    }

    // -------------------------------------------------------------------------
    // bulkToggleTargets — UI-05 bulk toggle
    // -------------------------------------------------------------------------

    @Test
    fun bulkToggleTargets_excludesDisabledIds() {
        val tools =
            listOf(
                descriptor("t1", "Tool One"),
                descriptor("t2", "Tool Two"),
                descriptor("t3", "Tool Three"),
            )
        val disabledIds = setOf("t2")
        val result = McpToolTabModel.bulkToggleTargets(tools, "", disabledIds)

        assertEquals(2, result.size)
        assertFalse(result.any { it.id == "t2" })
        assertTrue(result.any { it.id == "t1" })
        assertTrue(result.any { it.id == "t3" })
    }

    @Test
    fun bulkToggleTargets_filterApplied() {
        val tools =
            listOf(
                descriptor("t1", "Proxy History", description = "Shows proxy items"),
                descriptor("t2", "Scanner Issues", description = "Shows scanner findings"),
                descriptor("t3", "Site Map", description = "Shows site map entries"),
            )
        // Query matches only "Proxy History" by title
        val result = McpToolTabModel.bulkToggleTargets(tools, "proxy", emptySet())

        assertEquals(1, result.size)
        assertEquals("t1", result[0].id)
    }

    @Test
    fun bulkToggleTargets_allVisibleWhenQueryBlankAndNoDisabledIds() {
        val tools =
            listOf(
                descriptor("t1", "Tool One"),
                descriptor("t2", "Tool Two"),
                descriptor("t3", "Tool Three"),
            )
        val result = McpToolTabModel.bulkToggleTargets(tools, "", emptySet())

        assertEquals(3, result.size)
    }

    // -------------------------------------------------------------------------
    // categoryGroups
    // -------------------------------------------------------------------------

    @Test
    fun categoryGroups_sortedAlphabetically() {
        val tools =
            listOf(
                descriptor("u1", "Encode", category = "Utilities"),
                descriptor("b1", "Pause", category = "Burp Control"),
                descriptor("h1", "Proxy History", category = "History"),
            )
        val groups = McpToolTabModel.categoryGroups(tools)

        assertEquals(listOf("Burp Control", "History", "Utilities"), groups.keys.toList())
    }

    @Test
    fun categoryGroups_toolsWithinGroupSortedByTitle() {
        val tools =
            listOf(
                descriptor("z", "Zap", category = "Requests"),
                descriptor("a", "Alpha", category = "Requests"),
            )
        val groups = McpToolTabModel.categoryGroups(tools)
        val titles = groups.getValue("Requests").map { it.title }

        assertEquals(listOf("Alpha", "Zap"), titles)
    }
}
