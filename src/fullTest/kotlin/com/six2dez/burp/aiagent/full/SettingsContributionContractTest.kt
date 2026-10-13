package com.six2dez.burp.aiagent.full

import burp.api.montoya.MontoyaApi
import burp.api.montoya.persistence.Preferences
import com.six2dez.burp.aiagent.InMemoryPreferences
import com.six2dez.burp.aiagent.config.AgentSettingsRepository
import com.six2dez.burp.aiagent.config.SecretCipher
import com.six2dez.burp.aiagent.spi.Plugins
import com.six2dez.burp.aiagent.spi.SettingsContribution
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.Answers
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.lang.reflect.Modifier
import java.util.concurrent.CopyOnWriteArraySet

/**
 * Phase 29 plan 29-17 / D-10 amended, D-08 — the contract every full-build [SettingsContribution] keeps.
 *
 * - [SettingsContribution.sectionId] is non-blank and unique: it is the section key a future settings
 *   export would use.
 * - [SettingsContribution.ownedKeys] are non-blank and pairwise disjoint, so no two contributions write
 *   the same preference.
 * - No owned key is a core key. The core key set is taken two ways and both must be clean: every
 *   `KEY_*` String constant of the `AgentSettingsRepository` companion (read reflectively, so a new core
 *   key is covered without editing this test) plus the cipher's master-key preference, and every key the
 *   core repository actually reads, writes or deletes during a load, a save and a Restore defaults save
 *   over a fresh node. The second set is what makes D-08 hold in practice: the store build runs the
 *   same core code, so if that code touched a plug-in key the store build would read, overwrite or
 *   delete a full-only value.
 */
class SettingsContributionContractTest {
    private val contributions = Plugins.load(SettingsContribution::class.java)

    @Test
    fun theEightFullBuildContributionsAreLoaded() {
        assertEquals(8, contributions.size, "contributions: ${contributions.map { it.javaClass.name }}")
    }

    @Test
    fun sectionIdsAreNonBlankAndUnique() {
        val ids = contributions.map { it.sectionId }
        assertTrue(ids.none { it.isBlank() }, "blank sectionId in $ids")
        assertEquals(ids.size, ids.toSet().size, "duplicate sectionId in $ids")
    }

    @Test
    fun ownedKeysAreNonBlankAndPairwiseDisjoint() {
        val seen = mutableMapOf<String, String>()
        contributions.forEach { contribution ->
            val keys = contribution.ownedKeys()
            assertTrue(keys.isNotEmpty(), "${contribution.sectionId} owns no key")
            keys.forEach { key ->
                assertTrue(key.isNotBlank(), "${contribution.sectionId} owns a blank key")
                val previous = seen.put(key, contribution.sectionId)
                assertEquals(null, previous, "key $key is owned by both $previous and ${contribution.sectionId}")
            }
        }
    }

    @Test
    fun noOwnedKeyIsADeclaredCoreKey() {
        val coreKeys = declaredCoreKeys()
        assertTrue(coreKeys.size > MIN_DECLARED_CORE_KEYS, "the reflective core key read found only $coreKeys")
        assertTrue("backend.preferred" in coreKeys, "the reflective read must see the companion's private keys")
        val clashes = ownedKeys().filter { it in coreKeys }
        assertEquals(emptyList<String>(), clashes, "contribution keys that are core AgentSettings keys")
    }

    @Test
    fun noOwnedKeyIsReadWrittenOrDeletedByTheCoreRepository() {
        val prefs = RecordingPreferences(InMemoryPreferences())
        val api = mock<MontoyaApi>(defaultAnswer = Answers.RETURNS_DEEP_STUBS)
        whenever(api.persistence().preferences()).thenReturn(prefs)
        val repository = AgentSettingsRepository(api)

        repository.save(repository.load())
        repository.save(repository.defaultSettings())
        AgentSettingsRepository(api).load()

        assertTrue(prefs.touched.size > MIN_DECLARED_CORE_KEYS, "the recorder saw only ${prefs.touched}")
        val clashes = ownedKeys().filter { it in prefs.touched }
        assertEquals(emptyList<String>(), clashes, "contribution keys the core repository touched (D-08)")
    }

    private fun ownedKeys(): List<String> = contributions.flatMap { it.ownedKeys() }

    /** Every `KEY_*` String constant of the repository companion, plus the cipher's master-key preference. */
    private fun declaredCoreKeys(): Set<String> =
        AgentSettingsRepository::class.java.declaredFields
            .filter { Modifier.isStatic(it.modifiers) && it.type == String::class.java && it.name.startsWith("KEY_") }
            .map { field ->
                field.isAccessible = true
                field.get(null) as String
            }.toSet() + SecretCipher.MASTER_KEY_PREF_KEY

    /** A [Preferences] that records every key read, written or deleted, delegating storage to [inner]. */
    private class RecordingPreferences(
        private val inner: InMemoryPreferences,
    ) : Preferences by inner {
        val touched: MutableSet<String> = CopyOnWriteArraySet()

        override fun getString(key: String): String? = inner.getString(key).also { touched += key }

        override fun getBoolean(key: String): Boolean? = inner.getBoolean(key).also { touched += key }

        override fun getByte(key: String): Byte? = inner.getByte(key).also { touched += key }

        override fun getShort(key: String): Short? = inner.getShort(key).also { touched += key }

        override fun getInteger(key: String): Int? = inner.getInteger(key).also { touched += key }

        override fun getLong(key: String): Long? = inner.getLong(key).also { touched += key }

        override fun setString(
            key: String,
            value: String?,
        ) = inner.setString(key, value).also { touched += key }

        override fun setBoolean(
            key: String,
            value: Boolean,
        ) = inner.setBoolean(key, value).also { touched += key }

        override fun setInteger(
            key: String,
            value: Int,
        ) = inner.setInteger(key, value).also { touched += key }

        override fun setLong(
            key: String,
            value: Long,
        ) = inner.setLong(key, value).also { touched += key }

        override fun deleteString(key: String) = inner.deleteString(key).also { touched += key }

        override fun deleteBoolean(key: String) = inner.deleteBoolean(key).also { touched += key }

        override fun deleteInteger(key: String) = inner.deleteInteger(key).also { touched += key }

        override fun deleteLong(key: String) = inner.deleteLong(key).also { touched += key }
    }

    private companion object {
        /** A floor well under the ~130 core keys, so an empty or broken read cannot pass vacuously. */
        const val MIN_DECLARED_CORE_KEYS = 50
    }
}
