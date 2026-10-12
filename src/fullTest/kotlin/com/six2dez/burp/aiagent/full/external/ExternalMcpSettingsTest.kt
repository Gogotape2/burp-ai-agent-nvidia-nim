package com.six2dez.burp.aiagent.full.external

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.TestSettings
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.SecretCipher
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpTransport
import com.six2dez.burp.aiagent.spi.PluginSettingsStore
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import com.six2dez.burp.aiagent.spi.SettingsContributionContext
import com.six2dez.burp.aiagent.spi.SettingsSlot
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.awt.Component
import java.awt.Container
import java.util.Base64
import javax.swing.JComboBox
import javax.swing.SwingUtilities

/**
 * Phase 29 / NET-02, D-06, BUILD-03 (T-29-29, T-29-32): the full build's external-MCP plug-in owns the
 * server list under its 1.0.1 key `mcp.external.servers.v1`, through the repository's one
 * PluginSettingsStore and so its one SecretCipher and master key.
 *
 * The 1.0.1 blob is rebuilt here exactly as the 1.0.1 core wrote it (a JSON array whose per-field
 * `bearerToken` is a SecretCipher ENC1 envelope, the key name passed only as a logging label), because
 * an upgraded install has that blob on disk and must load it unchanged.
 */
class ExternalMcpSettingsTest {
    private val prefs = InMemoryPreferences()
    private val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
    private val store: PluginSettingsStore
    private val errors = mutableListOf<String>()

    init {
        whenever(api.persistence().preferences()).thenReturn(prefs)
        store = AgentSettingsRepository(api).pluginSettings()
    }

    private fun settings(): ExternalMcpSettings = ExternalMcpSettings(store) { errors += it }

    /** Writes [configs] as the 1.0.1 core did: each non-blank token through SecretCipher, then Jackson. */
    private fun write101Blob(
        configs: List<ExternalMcpServerConfig>,
        cipher: SecretCipher = SecretCipher(prefs),
        logKey: String = KEY,
    ) {
        val encrypted =
            configs.map { config ->
                config.copy(bearerToken = if (config.bearerToken.isBlank()) "" else cipher.encrypt(config.bearerToken, logKey))
            }
        prefs.strings[KEY] = MAPPER.writeValueAsString(encrypted)
    }

    private fun storedTokens(): List<String> = MAPPER.readValue(prefs.strings.getValue(KEY), Array<ExternalMcpServerConfig>::class.java).map { it.bearerToken }

    @Test
    fun aBlobWrittenBy101LoadsWithThePlaintextTokens() {
        write101Blob(listOf(SSE_SERVER, STDIO_SERVER))

        val loaded = settings().load()

        assertEquals(listOf(SSE_SERVER, STDIO_SERVER), loaded, "every field, the plaintext token included")
        assertTrue(errors.isEmpty(), "a valid blob logs nothing: $errors")
    }

    @Test
    fun saveThenLoadRoundTripsWithPerFieldEncryptionAndNoDoubleEncryption() {
        settings().save(listOf(SSE_SERVER, STDIO_SERVER))

        val blob = prefs.strings.getValue(KEY)
        assertFalse(blob.startsWith("ENC1:"), "the blob itself is plain JSON; only the token field is encrypted")
        assertFalse(blob.contains(SSE_SERVER.bearerToken), "the plaintext token never reaches the preferences")
        val tokens = storedTokens()
        assertTrue(tokens[0].startsWith("ENC1:") && !tokens[0].startsWith("ENC1:ENC1:"), "one ENC1 level: ${tokens[0]}")
        assertEquals("", tokens[1], "a blank token is stored blank, not encrypted")

        val reloaded = settings().load()
        assertEquals(listOf(SSE_SERVER, STDIO_SERVER), reloaded)
        settings().save(reloaded)
        assertFalse(storedTokens()[0].startsWith("ENC1:ENC1:"), "a second save does not double-encrypt")
        assertEquals(listOf(SSE_SERVER, STDIO_SERVER), settings().load())
    }

    @Test
    fun anEmptyListIsStoredAsBlankNotAsTheEmptyArraySentinel() {
        settings().save(listOf(SSE_SERVER))
        settings().save(emptyList())

        assertEquals("", prefs.strings[KEY], "#81: an empty list is stored as \"\", never \"[]\"")
    }

    @Test
    fun blankAndTheEmptyArraySentinelLoadEmptyWithoutInvokingJackson() {
        var parses = 0
        val counting = ExternalMcpSettings(store, { errors += it }) { parses++; listOf(SSE_SERVER) }

        listOf(null, "", "   ", "[]", " [] ").forEach { stored ->
            if (stored == null) prefs.strings.remove(KEY) else prefs.strings[KEY] = stored
            assertEquals(emptyList<ExternalMcpServerConfig>(), counting.load(), "stored ${stored?.let { "\"$it\"" }}")
        }
        assertEquals(0, parses, "#81: blank and \"[]\" never reach Jackson")

        prefs.strings[KEY] = "[{\"name\":\"x\",\"transport\":\"SSE\"}]"
        assertEquals(listOf(SSE_SERVER), counting.load(), "a real blob does reach the parser")
        assertEquals(1, parses)
    }

    @Test
    fun aMalformedBlobLoadsEmptyAndTheLogNamesOnlyTheKey() {
        val secret = "ghp_leakedSecretValue1234"
        prefs.strings[KEY] = "[{\"name\":\"s\",\"transport\":\"SSE\",\"bearerToken\":\"$secret\""

        assertEquals(emptyList<ExternalMcpServerConfig>(), settings().load())

        assertEquals(1, errors.size, "one error line: $errors")
        assertTrue(errors.single().contains(KEY), "the line names the key: ${errors.single()}")
        assertFalse(errors.single().contains(secret), "the line never carries the stored value: ${errors.single()}")
        assertFalse(errors.single().contains("\"name\""), "no fragment of the blob is logged: ${errors.single()}")
    }

    @Test
    fun anyThrowableWhileParsingFailsSoft() {
        prefs.strings[KEY] = "[{\"name\":\"s\",\"transport\":\"SSE\"}]"
        val throwing = ExternalMcpSettings(store, { errors += it }) { throw NoClassDefFoundError("kotlin/reflect/jvm/internal/KClassImpl") }

        assertEquals(emptyList<ExternalMcpServerConfig>(), throwing.load(), "#81: an Error degrades like an Exception")
        assertEquals(1, errors.size, "$errors")
        assertTrue(errors.single().contains(KEY) && errors.single().contains("NoClassDefFoundError"), errors.single())
        assertFalse(errors.single().contains("kotlin/reflect"), "the throwable message is not logged: ${errors.single()}")
    }

    @Test
    fun aTokenWithCorruptedAuthenticatedCiphertextDoesNotDecrypt() {
        write101Blob(listOf(SSE_SERVER))
        val stored = storedTokens().single()
        val envelope = Base64.getDecoder().decode(stored.removePrefix("ENC1:"))
        envelope[envelope.size - 1] = (envelope[envelope.size - 1].toInt() xor 0x01).toByte()
        val tampered = "ENC1:" + Base64.getEncoder().encodeToString(envelope)
        prefs.strings[KEY] = MAPPER.writeValueAsString(listOf(SSE_SERVER.copy(bearerToken = tampered)))

        val loaded = settings().load().single()

        assertEquals("", loaded.bearerToken, "GCM rejects the tampered envelope; it fails soft to blank")
        assertEquals(SSE_SERVER.copy(bearerToken = ""), loaded, "the rest of the entry still loads")
    }

    @Test
    fun aTokenEncryptedUnderAnotherMasterKeyDoesNotDecrypt() {
        write101Blob(listOf(SSE_SERVER), cipher = SecretCipher(InMemoryPreferences()))

        assertEquals("", settings().load().single().bearerToken, "a second master key is not this install's key")
    }

    @Test
    fun aDifferentLoggingKeyDoesNotPreventDecryption() {
        // The key name is a logging label, not authenticated data (ENC1 compatibility, user decision 4b18fb7).
        write101Blob(listOf(SSE_SERVER), logKey = "some.other.key")

        assertEquals(SSE_SERVER.bearerToken, settings().load().single().bearerToken)
    }

    // ── The MCP-tab contribution ─────────────────────────────────────────────────────────────────

    private val context =
        SettingsContributionContext(
            api = api,
            store = store,
            coreSettings = { TestSettings.baselineSettings() },
            dialogParent = { null },
            testConnection = {},
        )

    @Test
    fun theContributionOwnsOnlyTheServerListKeyOnTheMcpTab() {
        val contribution = ExternalMcpContribution()

        assertEquals(setOf(KEY), contribution.ownedKeys())
        assertEquals("mcp.external", contribution.sectionId)
        assertEquals(SettingsSlot.MCP_TAB, contribution.slot)
        assertEquals(
            listOf(ExternalMcpContribution::class.java.name),
            Plugins.load(SettingsContribution::class.java).filter { it.slot == SettingsSlot.MCP_TAB }.map { it.javaClass.name },
            "the full build's one MCP-tab contribution is registered through the services file",
        )
    }

    @Test
    fun theContributionShowsTheStoredListAndPersistsWhatThePanelHolds() {
        write101Blob(listOf(SSE_SERVER))
        val contribution = ExternalMcpContribution()

        onEdt {
            contribution.createComponent(context)
            assertEquals(ExternalServersSnapshot(listOf(SSE_SERVER)), contribution.collect(), "the panel starts from the stored list")
            contribution.applyToUi(ExternalServersSnapshot(listOf(SSE_SERVER, STDIO_SERVER)))
        }
        val snapshot = onEdtResult { contribution.collect() }
        contribution.persist(snapshot, store)

        assertEquals(listOf(SSE_SERVER, STDIO_SERVER), settings().load())
        assertEquals(ExternalServersSnapshot(emptyList()), contribution.defaults())
    }

    @Test
    fun onCoreSettingsAppliedForwardsStdioEnabledToThePanel() {
        val contribution = ExternalMcpContribution()
        val stdioOn = TestSettings.baselineSettings().let { it.copy(mcpSettings = it.mcpSettings.copy(stdioEnabled = true)) }
        val stdioOff = stdioOn.copy(mcpSettings = stdioOn.mcpSettings.copy(stdioEnabled = false))

        onEdt {
            val component = contribution.createComponent(context.copyWith { stdioOff })
            val transport = transportCombo(component)
            assertEquals(listOf("SSE"), items(transport), "stdio off: SSE only")

            contribution.onCoreSettingsApplied(stdioOn)
            assertEquals(listOf("SSE", "stdio"), items(transport), "stdio on: the panel offers stdio")

            contribution.onCoreSettingsApplied(stdioOff)
            assertEquals(listOf("SSE"), items(transport), "stdio off again: SSE only")
        }
    }

    private fun SettingsContributionContext.copyWith(core: () -> com.six2dez.burp.aiagent.config.AgentSettings) =
        SettingsContributionContext(api, store, core, dialogParent, testConnection)

    private fun transportCombo(root: Component): JComboBox<*> =
        descendants(root).filterIsInstance<JComboBox<*>>().single { combo ->
            (0 until combo.itemCount).any { combo.getItemAt(it) == "SSE" }
        }

    private fun items(combo: JComboBox<*>): List<Any?> = (0 until combo.itemCount).map { combo.getItemAt(it) }

    private fun descendants(root: Component): List<Component> =
        listOf(root) + ((root as? Container)?.components?.flatMap { descendants(it) } ?: emptyList())

    private fun onEdt(body: () -> Unit) = SwingUtilities.invokeAndWait(body)

    private fun <T> onEdtResult(body: () -> T): T {
        var result: T? = null
        SwingUtilities.invokeAndWait { result = body() }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    private companion object {
        const val KEY = "mcp.external.servers.v1"
        val MAPPER = JsonMapper.builder().build().registerKotlinModule()

        val SSE_SERVER =
            ExternalMcpServerConfig(
                name = "x",
                transport = ExternalMcpTransport.SSE,
                url = "https://mcp.example.com/sse",
                bearerToken = "s3cr3t-bearer-token",
            )
        val STDIO_SERVER =
            ExternalMcpServerConfig(
                name = "local",
                transport = ExternalMcpTransport.STDIO,
                command = listOf("npx", "server"),
                extraArgs = listOf("--flag"),
                envVars = mapOf("A" to "1"),
                enabled = false,
            )
    }
}
