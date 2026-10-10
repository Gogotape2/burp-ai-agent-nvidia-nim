package com.six2dez.burp.aiagent.spi

/**
 * Phase 29 / D-06 — the small settings contract plug-ins use to read and write their own Burp
 * preference keys. Obtain it from `AgentSettingsRepository.pluginSettings()`: it is backed by the
 * repository's one `Preferences` instance and its one `SecretCipher`, so plug-in secrets share the
 * per-install master key and the values the core already encrypted keep decrypting.
 *
 * Rules every plug-in follows:
 *  - Own keys only. A plug-in never reads or writes a key the core `AgentSettings` owns.
 *  - New plug-in keys are prefixed `full.`.
 *  - Keys inherited from 1.0.1 keep their exact names, so an upgrade keeps the stored values (D-11).
 *  - Secrets are stored only as [encrypt] output and read back through [decrypt], passing the
 *    preference key name as [encrypt]'s `keyName`, as the core does.
 *  - There is no delete. The store build never deletes a key (D-08), and the full build has no reason
 *    to: an unused key is left in place.
 *
 * Setters run under the repository's write lock, so a plug-in write never interleaves a settings
 * save. They do not notify the repository's change listeners: plug-in keys are not part of the
 * `AgentSettings` snapshot.
 */
interface PluginSettingsStore {
    fun getString(key: String): String?

    fun setString(
        key: String,
        value: String,
    )

    fun getBoolean(key: String): Boolean?

    fun setBoolean(
        key: String,
        value: Boolean,
    )

    fun getInteger(key: String): Int?

    fun setInteger(
        key: String,
        value: Int,
    )

    /**
     * Encrypts [plain] with the repository's `SecretCipher` into its `ENC1:` envelope.
     *
     * [keyName] is the preference key the value is stored under. `SecretCipher` uses it only to name
     * the key in failure logs; it is NOT bound into the ciphertext as authenticated data, so the result
     * decrypts under any [keyName]. Pass the key name anyway, exactly as the core does, so a future
     * cipher that binds it changes no caller.
     */
    fun encrypt(
        plain: String,
        keyName: String,
    ): String

    /**
     * Decrypts a value produced by [encrypt] or by the core's own `SecretCipher.encrypt`. A value
     * without the `ENC1:` prefix is returned unchanged (legacy plaintext), and an envelope that does
     * not authenticate returns "" (fail-soft, as everywhere in the core). See [encrypt] on [keyName].
     */
    fun decrypt(
        stored: String,
        keyName: String,
    ): String
}
