package com.six2dez.burp.aiagent

import burp.api.montoya.persistence.Preferences
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Phase 29 (D-06, D-08) — a complete in-memory [Preferences] for tests, shared so new tests stop
 * defining their own private mock-backed fakes.
 *
 * Every typed store Montoya offers is a real map, and every set and delete is recorded per key in
 * [writes] and [deletes], so a test can assert "this key was never written" or "this key was never
 * deleted" (D-08: the store build must never delete a key it does not own) rather than only reading
 * the final value back.
 *
 * Thread-safe enough for the concurrency tests that use it: the maps are concurrent and the logs are
 * copy-on-write.
 */
class InMemoryPreferences : Preferences {
    val strings: MutableMap<String, String> = ConcurrentHashMap()
    val booleans: MutableMap<String, Boolean> = ConcurrentHashMap()
    val bytes: MutableMap<String, Byte> = ConcurrentHashMap()
    val shorts: MutableMap<String, Short> = ConcurrentHashMap()
    val integers: MutableMap<String, Int> = ConcurrentHashMap()
    val longs: MutableMap<String, Long> = ConcurrentHashMap()

    /** Every set, in call order, as the key written. */
    val writes: MutableList<String> = CopyOnWriteArrayList()

    /** Every delete, in call order, as the key deleted. */
    val deletes: MutableList<String> = CopyOnWriteArrayList()

    fun writeCount(key: String): Int = writes.count { it == key }

    fun deleteCount(key: String): Int = deletes.count { it == key }

    private fun <T : Any> put(
        map: MutableMap<String, T>,
        key: String,
        value: T?,
    ) {
        writes += key
        // Montoya treats a null value as "no value"; a concurrent map cannot hold null.
        if (value == null) map.remove(key) else map[key] = value
    }

    private fun <T : Any> delete(
        map: MutableMap<String, T>,
        key: String,
    ) {
        deletes += key
        map.remove(key)
    }

    override fun getString(key: String): String? = strings[key]

    override fun setString(
        key: String,
        value: String?,
    ) = put(strings, key, value)

    override fun deleteString(key: String) = delete(strings, key)

    override fun stringKeys(): Set<String> = strings.keys.toSet()

    override fun getBoolean(key: String): Boolean? = booleans[key]

    override fun setBoolean(
        key: String,
        value: Boolean,
    ) = put(booleans, key, value)

    override fun deleteBoolean(key: String) = delete(booleans, key)

    override fun booleanKeys(): Set<String> = booleans.keys.toSet()

    override fun getByte(key: String): Byte? = bytes[key]

    override fun setByte(
        key: String,
        value: Byte,
    ) = put(bytes, key, value)

    override fun deleteByte(key: String) = delete(bytes, key)

    override fun byteKeys(): Set<String> = bytes.keys.toSet()

    override fun getShort(key: String): Short? = shorts[key]

    override fun setShort(
        key: String,
        value: Short,
    ) = put(shorts, key, value)

    override fun deleteShort(key: String) = delete(shorts, key)

    override fun shortKeys(): Set<String> = shorts.keys.toSet()

    override fun getInteger(key: String): Int? = integers[key]

    override fun setInteger(
        key: String,
        value: Int,
    ) = put(integers, key, value)

    override fun deleteInteger(key: String) = delete(integers, key)

    override fun integerKeys(): Set<String> = integers.keys.toSet()

    override fun getLong(key: String): Long? = longs[key]

    override fun setLong(
        key: String,
        value: Long,
    ) = put(longs, key, value)

    override fun deleteLong(key: String) = delete(longs, key)

    override fun longKeys(): Set<String> = longs.keys.toSet()
}
