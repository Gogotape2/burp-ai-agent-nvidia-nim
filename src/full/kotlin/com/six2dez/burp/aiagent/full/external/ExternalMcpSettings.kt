package com.six2dez.burp.aiagent.full.external

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import com.six2dez.burp.aiagent.mcp.external.ExternalMcpServerConfig
import com.six2dez.burp.aiagent.spi.PluginSettingsStore

/**
 * Phase 29 / NET-02, D-06, D-11 — the external-MCP plug-in's persistence of the server list.
 *
 * Moved verbatim from the 1.0.1 core (`AgentSettingsRepository.saveExternalMcpServers` and
 * `loadExternalMcpServers`), so an upgraded full install loads the list 1.0.1 left on disk:
 * - The key is unchanged: [KEY] (`mcp.external.servers.v1`).
 * - Each server's `bearerToken` is encrypted on its own with the repository's one `SecretCipher`, through
 *   [PluginSettingsStore.encrypt] / [PluginSettingsStore.decrypt]. The key name is passed as a logging
 *   label only; it is not bound into the ENC1 envelope, which is what keeps 1.0.1 tokens decrypting
 *   (user decision 4b18fb7: the cipher does not change). The JSON blob itself is not encrypted, and a
 *   blank token is stored blank.
 * - An empty list is stored as "" (not "[]"), and a blank or "[]" value loads as an empty list without
 *   invoking Jackson (#81: deserializing "[]" through jackson-module-kotlin can surface a kotlin-reflect
 *   Throwable in Burp's isolated classloader).
 * - Any Throwable while parsing fails soft to an empty list, and every log line names only the key and
 *   the throwable's type, never a stored value (T-16-02-LOG).
 *
 * The store build has neither this class nor any code that reads, writes or deletes [KEY] (D-08).
 *
 * @param logError writes one line to Burp's error output.
 * @param parse the JSON-to-list step; tests replace it to prove the #81 short-circuit and fail-soft.
 */
class ExternalMcpSettings internal constructor(
    private val store: PluginSettingsStore,
    private val logError: (String) -> Unit,
    private val parse: (String) -> List<ExternalMcpServerConfig>,
) {
    constructor(store: PluginSettingsStore, logError: (String) -> Unit) : this(store, logError, ::parseWithJackson)

    /**
     * The stored list with PLAINTEXT tokens. Callers must not decrypt them again. A token that does not
     * authenticate (tampered, or written under another install's master key) loads as "".
     *
     * `TooGenericExceptionCaught`: catching Throwable is the #81 fix itself, not an oversight.
     */
    @Suppress("TooGenericExceptionCaught")
    fun load(): List<ExternalMcpServerConfig> {
        val json = store.getString(KEY)
        // #81: blank and the empty-array sentinel are "no servers", decided without Jackson.
        if (json.isNullOrBlank() || json.trim() == "[]") return emptyList()
        return try {
            parse(json).map { config ->
                val plainToken =
                    if (config.bearerToken.isBlank()) {
                        ""
                    } else {
                        store.decrypt(config.bearerToken, KEY)
                    }
                config.copy(bearerToken = plainToken)
            }
        } catch (e: Throwable) {
            // Fail-soft per D-01: a parse failure never aborts extension load. Throwable, not Exception, so a
            // kotlin-reflect Error degrades the same way (#81). Key name and type only (T-16-02-LOG).
            logError("ExternalMcpSettings.load: parse failed for key $KEY (${e.javaClass.simpleName})")
            emptyList()
        }
    }

    /**
     * Stores [configs], each non-blank token encrypted on its own. An encryption failure propagates to the
     * caller (the settings host reports it as "Save failed"), as it did from the 1.0.1 core save.
     *
     * `TooGenericExceptionCaught`: a serialization failure of any kind must log the key name only.
     */
    @Suppress("TooGenericExceptionCaught")
    fun save(configs: List<ExternalMcpServerConfig>) {
        val encryptedList =
            configs.map { config ->
                val storedToken =
                    if (config.bearerToken.isBlank()) {
                        ""
                    } else {
                        store.encrypt(config.bearerToken, KEY)
                    }
                config.copy(bearerToken = storedToken)
            }
        try {
            // Store an empty list as "" (not "[]") so a later load never deserializes the sentinel (#81).
            val json = if (encryptedList.isEmpty()) "" else MAPPER.writeValueAsString(encryptedList)
            store.setString(KEY, json)
        } catch (_: Exception) {
            // Never log the token value; the key name only (T-16-02-LOG).
            logError("ExternalMcpSettings.save: serialization failed for key: $KEY")
        }
    }

    companion object {
        /** The 1.0.1 key, unchanged (D-11). */
        const val KEY: String = "mcp.external.servers.v1"

        // Registered with the Kotlin module so data class defaults and named parameters work, as the 1.0.1
        // core mapper was.
        private val MAPPER: ObjectMapper by lazy {
            JsonMapper.builder().build().registerKotlinModule()
        }

        private fun parseWithJackson(json: String): List<ExternalMcpServerConfig> = MAPPER.readValue(json, Array<ExternalMcpServerConfig>::class.java).toList()
    }
}
