package com.mustafadakhel.oag

class ConcurrentLruMap<K, V>(private val maxEntries: Int) {
    private val lock = Any()
    private val map = LinkedHashMap<K, V>(16, 0.75f, true)

    fun get(key: K): V? = synchronized(lock) { map[key] }

    fun put(key: K, value: V) = synchronized(lock) {
        map[key] = value
        evictIfNeeded()
    }

    fun getOrPut(key: K, defaultValue: () -> V): V =
        synchronized(lock) {
            map.getOrPut(key, defaultValue).also { evictIfNeeded() }
        }

    fun remove(key: K): V? = synchronized(lock) { map.remove(key) }

    fun clear() = synchronized(lock) { map.clear() }

    fun size(): Int = synchronized(lock) { map.size }

    fun compute(key: K, remapping: (V?) -> V?): V? = synchronized(lock) {
        val result = remapping(map[key])
        if (result != null) { map[key] = result; evictIfNeeded() } else map.remove(key)
        result
    }

    fun <R> withLock(action: MutableMap<K, V>.() -> R): R =
        synchronized(lock) { map.action().also { evictIfNeeded() } }

    private fun evictIfNeeded() {
        while (map.size > maxEntries) {
            val eldest = map.entries.iterator().next()
            map.remove(eldest.key)
        }
    }
}
