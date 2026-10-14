package com.six2dez.burp.aiagent.full.autoqueue

import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.scanner.ActiveAiScanner
import com.six2dez.burp.aiagent.scanner.ActiveScanTarget
import com.six2dez.burp.aiagent.scanner.AiIssueItem
import com.six2dez.burp.aiagent.scanner.InjectionPoint
import com.six2dez.burp.aiagent.scanner.InjectionType
import com.six2dez.burp.aiagent.scanner.PassiveScanCheckRig
import com.six2dez.burp.aiagent.scanner.ScanMode
import com.six2dez.burp.aiagent.scanner.SuggestedTargetList
import com.six2dez.burp.aiagent.scanner.VulnClass
import com.six2dez.burp.aiagent.scanner.VulnHint
import com.six2dez.burp.aiagent.scanner.handleParsedAiIssues
import com.six2dez.burp.aiagent.spi.PluginHost
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.util.Collections

/**
 * Phase 32 SC1 and SCAN-01 in the full build — the twin of the store build's
 * `PassiveScanNoTargetTrafficTest`, with the auto-queue plug-in installed.
 *
 * The auto-queue is opt-in and OFF by default: with its key absent, a passive finding's suggested
 * targets stay in the core list [com.six2dez.burp.aiagent.scanner.PassiveAiScanner.suggestedTargets]
 * and nothing reaches the active queue or the target. With the key on, the targets the active scanner
 * really queued leave the core list (D-08) and the "[AutoQueue] Queued N" line counts only them
 * (31-REVIEW IN-06). The plug-in never replaces the core list: the list is the same object before and
 * after install, and a full list still offers every new suggestion to the sink.
 *
 * Each case uses its own host because ScanKnowledgeBase is process-wide.
 */
class FullPassiveScanNoTargetTrafficTest {
    @Test
    fun withTheAutoQueueKeyAbsentAPassiveFindingStaysInTheListAndSendsNothing() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val store = pluginStore(rig)
            val http = mockHttp(rig)
            val pluginLog = Collections.synchronizedList(mutableListOf<String>())
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            val plugin = AutoQueuePlugin()
            try {
                active.setEnabled(true)
                rig.scanner.setEnabled(true)
                plugin.install(PluginHost(rig.api, store, rig.scanner, active) { pluginLog += it })
                val host = "full-off.example"

                aiSqlInjection(rig, rig.csrfPost(host))

                val suggested = rig.scanner.suggestedTargets.snapshot()
                assertTrue(suggested.isNotEmpty(), "the finding's injection points become suggestions")
                assertEquals(setOf(VulnClass.SQLI), suggested.map { it.target.vulnHint.vulnClass }.toSet())
                assertTrue(suggested.all { it.url.contains(host) }, "every suggestion is on $host")
                assertEquals(0, active.getStatus().queueSize, "an absent key is OFF: nothing is queued")
                verifyNoInteractions(http)
                assertEquals(emptyList<String>(), autoQueueLines(pluginLog, rig), "no [AutoQueue] line")
            } finally {
                plugin.shutdown()
                active.shutdown()
            }
        }
    }

    @Test
    fun withTheAutoQueueOnAndTheGateRefusingTheListKeepsEveryEntryAndNothingIsLogged() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val store = pluginStore(rig)
            store.setBoolean(AutoQueuePlugin.KEY, true)
            val http = mockHttp(rig)
            whenever(rig.supervisor.refusalForSavedBackend(any())).thenReturn(REFUSAL)
            val pluginLog = Collections.synchronizedList(mutableListOf<String>())
            val active = ActiveAiScanner(rig.api, rig.supervisor, rig.audit) { rig.settings }
            val plugin = AutoQueuePlugin()
            try {
                active.setEnabled(true)
                rig.scanner.setEnabled(true)
                plugin.install(PluginHost(rig.api, store, rig.scanner, active) { pluginLog += it })

                aiSqlInjection(rig, rig.csrfPost("full-refused.example"))

                assertTrue(rig.scanner.suggestedTargets.count() > 0, "every suggestion stays in the list")
                val keysBefore = suggestedKeys(rig)
                aiSqlInjection(rig, rig.csrfPost("full-refused.example"))
                assertEquals(keysBefore, suggestedKeys(rig), "a repeat offer removes nothing")
                assertEquals(0, active.getStatus().queueSize, "the refused gate queues nothing")
                verifyNoInteractions(http)
                assertEquals(emptyList<String>(), autoQueueLines(pluginLog, rig), "IN-06: no [AutoQueue] Queued line")
                val pausedLines = synchronized(rig.output) { rig.output.filter { it.startsWith("[ActiveAiScanner] Paused: ") } }
                assertEquals(listOf("[ActiveAiScanner] Paused: $REFUSAL"), pausedLines, "one Paused line, no more")
            } finally {
                plugin.shutdown()
                active.shutdown()
            }
        }
    }

    @Test
    fun withTheAutoQueueOnAndTheScannerAcceptingTheQueuedTargetsLeaveTheList() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val store = pluginStore(rig)
            store.setBoolean(AutoQueuePlugin.KEY, true)
            val pluginLog = Collections.synchronizedList(mutableListOf<String>())
            val active = mock<ActiveAiScanner>()
            whenever(active.tryQueueTarget(any())).thenReturn(true)
            val plugin = AutoQueuePlugin()
            try {
                rig.scanner.setEnabled(true)
                plugin.install(PluginHost(rig.api, store, rig.scanner, active) { pluginLog += it })
                val host = "full-on.example"

                aiSqlInjection(rig, rig.csrfPost(host))

                val offered = argumentCaptor<ActiveScanTarget>()
                verify(active, atLeastOnce()).tryQueueTarget(offered.capture())
                assertTrue(offered.allValues.isNotEmpty(), "the finding's targets were offered")
                val onHost =
                    rig.scanner.suggestedTargets
                        .snapshot()
                        .filter { it.url.contains(host) }
                assertEquals(emptyList<Any>(), onHost, "D-08: every queued target left the list")
                assertEquals(
                    listOf("[AutoQueue] Queued ${offered.allValues.size} suggested target(s) to the Active Scanner"),
                    pluginLog.toList(),
                    "the count matches what the active scanner queued",
                )
            } finally {
                plugin.shutdown()
            }
        }
    }

    @Test
    fun thePluginKeepsTheCoreListAndAFullListStillOffersToTheSink() {
        PassiveScanCheckRig(sc1Settings()).use { rig ->
            val store = pluginStore(rig)
            val pluginLog = Collections.synchronizedList(mutableListOf<String>())
            val active = mock<ActiveAiScanner>()
            whenever(active.tryQueueTarget(any())).thenReturn(true)
            val plugin = AutoQueuePlugin()
            try {
                rig.scanner.setEnabled(true)
                val listBefore = rig.scanner.suggestedTargets
                plugin.install(PluginHost(rig.api, store, rig.scanner, active) { pluginLog += it })

                assertSame(listBefore, rig.scanner.suggestedTargets, "install does not replace the core list")
                assertTrue(rig.scanner.suggestedTargetSink is AutoQueueSink, "the plug-in's sink is installed")

                // With the key absent the list still fills and the sink queues nothing.
                aiSqlInjection(rig, rig.csrfPost("full-compose.example"))
                assertTrue(rig.scanner.suggestedTargets.count() > 0, "the core list fills next to the plug-in")
                verifyNoInteractions(active)

                // With the list at its cap, a new suggestion still reaches the sink.
                rig.scanner.suggestedTargets.addAll(fillers(SuggestedTargetList.DEFAULT_CAP))
                assertEquals(SuggestedTargetList.DEFAULT_CAP, rig.scanner.suggestedTargets.count())
                store.setBoolean(AutoQueuePlugin.KEY, true)
                aiSqlInjection(rig, rig.csrfPost("full-compose-full.example"))

                verify(active, atLeastOnce()).tryQueueTarget(any())
                assertEquals(1, pluginLog.size, "the sink was offered and queued: $pluginLog")
                assertSame(listBefore, rig.scanner.suggestedTargets, "still the same list after the offers")
            } finally {
                plugin.shutdown()
            }
        }
    }

    private fun aiSqlInjection(
        rig: PassiveScanCheckRig,
        requestResponse: HttpRequestResponse,
    ) {
        rig.scanner.handleParsedAiIssues(
            listOf(AiIssueItem(title = "SQL Injection", severity = "High", detail = "d", confidence = 90)),
            requestResponse,
            "LOW",
        )
    }

    private fun suggestedKeys(rig: PassiveScanCheckRig): List<String> =
        rig.scanner.suggestedTargets
            .snapshot()
            .map { it.key }

    private fun pluginStore(rig: PassiveScanCheckRig): PluginSettingsStore {
        whenever(rig.api.persistence().preferences()).thenReturn(InMemoryPreferences())
        return AgentSettingsRepository(rig.api).pluginSettings()
    }

    private fun mockHttp(rig: PassiveScanCheckRig): Http {
        val http = mock<Http>()
        whenever(rig.api.http()).thenReturn(http)
        return http
    }

    private fun autoQueueLines(
        pluginLog: List<String>,
        rig: PassiveScanCheckRig,
    ): List<String> {
        val output = synchronized(rig.output) { rig.output.toList() }
        return (synchronized(pluginLog) { pluginLog.toList() } + output).filter { it.startsWith("[AutoQueue]") }
    }

    private fun fillers(count: Int): List<ActiveScanTarget> {
        val request = mock<HttpRequestResponse>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        return (0 until count).map { index ->
            ActiveScanTarget(
                originalRequest = request,
                injectionPoint = InjectionPoint(InjectionType.URL_PARAM, "filler$index", "1"),
                vulnHint = VulnHint(VulnClass.SQLI, 90, "evidence"),
                priority = 40,
            )
        }
    }

    private fun sc1Settings(): AgentSettings =
        TestSettings.baselineSettings().copy(
            passiveAiEnabled = true,
            passiveAiScopeOnly = false,
            activeAiEnabled = true,
            activeAiScanMode = ScanMode.FULL,
        )

    private companion object {
        const val REFUSAL = "This build sends AI requests only while Burp's 'Use AI' setting is enabled."
    }
}
