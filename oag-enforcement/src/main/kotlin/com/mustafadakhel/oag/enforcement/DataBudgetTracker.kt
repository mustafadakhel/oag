package com.mustafadakhel.oag.enforcement

class DataBudgetTracker(
    maxEntries: Int = DEFAULT_MAX_LRU_ENTRIES
) {
    private val tracker = BudgetTracker(maxEntries)

    fun recordAndCheck(sessionId: String, host: String, bytes: Long, limit: Long): Boolean =
        tracker.recordAndCheck(compositeKey(sessionId, host), bytes, limit)

    fun currentUsage(sessionId: String, host: String): Long =
        tracker.currentUsage(compositeKey(sessionId, host))

    fun clear() = tracker.clear()
}

private const val KEY_SEPARATOR = "\u0000"

private fun compositeKey(sessionId: String, host: String): String =
    "$sessionId$KEY_SEPARATOR$host"
