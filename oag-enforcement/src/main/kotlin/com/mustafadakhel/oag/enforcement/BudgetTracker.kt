package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.ConcurrentLruMap

internal const val DEFAULT_MAX_LRU_ENTRIES = 10_000

class BudgetTracker(
    maxEntries: Int = DEFAULT_MAX_LRU_ENTRIES
) {
    private val usage = ConcurrentLruMap<String, Long>(maxEntries)

    fun recordAndCheck(key: String, amount: Long, limit: Long): Boolean {
        require(amount >= 0) { "Budget amount must not be negative" }
        val updated = requireNotNull(usage.compute(key) { current -> (current ?: 0L) + amount })
        return updated <= limit
    }

    fun currentUsage(key: String): Long = usage.get(key) ?: 0L

    fun clear() = usage.clear()
}
