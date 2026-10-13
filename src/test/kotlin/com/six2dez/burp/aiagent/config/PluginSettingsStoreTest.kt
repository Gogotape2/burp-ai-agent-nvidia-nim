package com.six2dez.burp.aiagent.config

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.SourceRoots
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Phase 29 / D-06 (T-29-15, T-29-16) — `AgentSettingsRepository.pluginSettings()`, the settings
 * contract plug-ins use for their own keys.
 *
 * It must sit on the repository's ONE Preferences instance and ONE SecretCipher: a second cipher would
 * be a second master key, and the secrets the core already encrypted would stop decrypting through the
 * plug-in. Its setters must take the repository's write lock so a plug-in write never interleaves a
 * settings save.
 */
class PluginSettingsStoreTest {
    @Test
    fun typedValuesRoundTripThroughTheStoreAndLandInTheRepositoryPreferences() {
        val (repo, prefs) = newRepository()
        val store = repo.pluginSettings()

        store.setString(STRING_KEY, "value-1")
        store.setBoolean(BOOLEAN_KEY, true)
        store.setInteger(INTEGER_KEY, 42)

        assertEquals("value-1", store.getString(STRING_KEY))
        assertEquals(true, store.getBoolean(BOOLEAN_KEY))
        assertEquals(42, store.getInteger(INTEGER_KEY))
        assertEquals("value-1", prefs.strings[STRING_KEY], "the store must write the repository's own Preferences")
        assertEquals(true, prefs.booleans[BOOLEAN_KEY])
        assertEquals(42, prefs.integers[INTEGER_KEY])
        assertNull(store.getString("full.test.absent"), "an absent key reads as null")
    }

    @Test
    fun aSecretTheCoreEncryptedDecryptsThroughTheStoreUnderTheSameKeyName() {
        val (repo, prefs) = newRepository()
        val defaults = repo.defaultSettings()
        repo.save(defaults.copy(mcpSettings = defaults.mcpSettings.copy(token = CORE_TOKEN)))

        val stored = prefs.strings[MCP_TOKEN_KEY].orEmpty()
        assertTrue(stored.startsWith("ENC1:"), "the core must have stored the MCP token encrypted")
        assertEquals(CORE_TOKEN, repo.pluginSettings().decrypt(stored, MCP_TOKEN_KEY))
    }

    @Test
    fun aPluginSecretIsEncryptedAtRestUnderTheSingleMasterKey() {
        val (repo, prefs) = newRepository()
        repo.save(repo.defaultSettings().copy(ollamaApiKey = "core-secret"))
        val encrypted = repo.pluginSettings().encrypt(PLUGIN_SECRET, PLUGIN_SECRET_KEY)

        assertTrue(encrypted.startsWith("ENC1:"), "a plug-in secret must be stored as an ENC1 envelope")
        assertFalse(encrypted.contains(PLUGIN_SECRET), "the plaintext must not appear in the envelope")
        assertEquals(PLUGIN_SECRET, repo.pluginSettings().decrypt(encrypted, PLUGIN_SECRET_KEY))

        // One master key: generated once, shared by the core saves and the plug-in store, and a fresh
        // repository over the same Preferences (the next Burp start) decrypts the plug-in value.
        assertEquals(1, prefs.writeCount(SecretCipher.MASTER_KEY_PREF_KEY), "the master key must be written exactly once")
        val (reopened, _) = newRepository(prefs)
        assertEquals(PLUGIN_SECRET, reopened.pluginSettings().decrypt(encrypted, PLUGIN_SECRET_KEY))
    }

    /**
     * Characterization, not a goal: SecretCipher uses the key name only as a log label, so it is not
     * bound into the ciphertext. Plan 29-07 assumed it was authenticated data; it is not, and binding it
     * would be a new envelope format (deferred-items.md). If a future cipher binds it, this test is the
     * one to change, consciously.
     */
    @Test
    fun theKeyNameIsALogLabelNotBoundIntoTheCiphertext() {
        val (repo, _) = newRepository()
        val store = repo.pluginSettings()
        val encrypted = store.encrypt(PLUGIN_SECRET, "full.test.a")
        assertEquals(PLUGIN_SECRET, store.decrypt(encrypted, "full.test.b"))
    }

    @Test
    fun aTamperedEnvelopeFailsSoftToEmpty() {
        val (repo, _) = newRepository()
        val store = repo.pluginSettings()
        val encrypted = store.encrypt(PLUGIN_SECRET, PLUGIN_SECRET_KEY)
        val tampered = encrypted.dropLast(4) + if (encrypted.endsWith("AAAA")) "BBBB" else "AAAA"
        assertEquals("", store.decrypt(tampered, PLUGIN_SECRET_KEY))
        assertEquals("legacy-plain", store.decrypt("legacy-plain", PLUGIN_SECRET_KEY), "a non-ENC1 value passes through")
    }

    @Test
    fun settersWaitForTheRepositoryWriteLock() {
        val (repo, prefs) = newRepository()
        repo.load()
        val store = repo.pluginSettings()
        val holding = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder =
            thread(name = "test-settings-lock-holder") {
                repo.update {
                    holding.countDown()
                    release.await(WAIT_SECONDS, TimeUnit.SECONDS)
                    it
                }
            }
        assertTrue(holding.await(WAIT_SECONDS, TimeUnit.SECONDS), "the holder must enter update{}")
        val writer = thread(name = "test-plugin-settings-writer") { store.setString(STRING_KEY, "after-lock") }
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS)
            while (writer.isAlive && writer.state != Thread.State.BLOCKED && System.nanoTime() < deadline) {
                Thread.sleep(POLL_MILLIS)
            }
            assertEquals(
                Thread.State.BLOCKED,
                writer.state,
                "a plug-in setter must block while another thread holds the repository write lock",
            )
            assertNull(prefs.strings[STRING_KEY], "the plug-in write must not land while the lock is held")
        } finally {
            release.countDown()
            holder.join(TimeUnit.SECONDS.toMillis(WAIT_SECONDS))
            writer.join(TimeUnit.SECONDS.toMillis(WAIT_SECONDS))
        }
        assertEquals("after-lock", prefs.strings[STRING_KEY])
    }

    @Test
    fun pluginWritesDoNotNotifyTheSettingsChangeListeners() {
        val (repo, _) = newRepository()
        var notified = 0
        repo.addChangeListener { notified++ }
        val store = repo.pluginSettings()
        store.setString(STRING_KEY, "v")
        store.setBoolean(BOOLEAN_KEY, false)
        store.setInteger(INTEGER_KEY, 7)
        assertEquals(0, notified, "plug-in keys are not part of the AgentSettings snapshot")
    }

    @Test
    fun theRepositoryConstructsTheOnlySecretCipherInProductionCode() {
        val sites =
            SourceRoots.kotlinFiles().flatMap { file ->
                file
                    .readLines()
                    .withIndex()
                    .filter { (_, line) ->
                        val code = line.trimStart()
                        !code.startsWith("//") && !code.startsWith("*") && CONSTRUCTION.containsMatchIn(code)
                    }.map { (index, _) -> "${SourceRoots.packageRelativePath(file)}:${index + 1}" }
            }
        assertEquals(1, sites.size, "exactly one SecretCipher construction expected, found $sites")
        assertTrue(sites.single().startsWith("config/AgentSettings.kt:"), "the one construction must be the repository's: $sites")
    }

    @Test
    fun inMemoryPreferencesRecordsWritesAndDeletesPerKey() {
        val prefs = InMemoryPreferences()
        prefs.setString("a", "1")
        prefs.setString("a", "2")
        prefs.setLong("b", 3L)
        prefs.deleteString("a")
        assertEquals(2, prefs.writeCount("a"))
        assertEquals(1, prefs.deleteCount("a"))
        assertEquals(0, prefs.deleteCount("b"))
        assertNull(prefs.getString("a"))
        assertEquals(3L, prefs.getLong("b"))
        assertEquals(setOf("b"), prefs.longKeys())
    }

    private fun newRepository(prefs: InMemoryPreferences = InMemoryPreferences()): Pair<AgentSettingsRepository, InMemoryPreferences> {
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        return AgentSettingsRepository(api) to prefs
    }

    private companion object {
        const val STRING_KEY = "full.test.string"
        const val BOOLEAN_KEY = "full.test.boolean"
        const val INTEGER_KEY = "full.test.integer"
        const val MCP_TOKEN_KEY = "mcp.token"
        const val CORE_TOKEN = "core-mcp-token-SENTINEL"
        const val PLUGIN_SECRET = "plugin-secret-SENTINEL"
        const val PLUGIN_SECRET_KEY = "full.test.secret"
        const val WAIT_SECONDS = 5L
        const val POLL_MILLIS = 5L

        /** A constructor call: `SecretCipher(` not preceded by `class `. */
        val CONSTRUCTION = Regex("""(?<!class )\bSecretCipher\(""")
    }
}
