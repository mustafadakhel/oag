package com.mustafadakhel.oag.enforcement

class TokenBudgetTracker(
    maxEntries: Int = DEFAULT_MAX_LRU_ENTRIES
) {
    private val tracker = BudgetTracker(maxEntries)

    fun recordAndCheck(sessionId: String, tokens: Long, limit: Long): Boolean =
        tracker.recordAndCheck(sessionId, tokens, limit)

    fun currentUsage(sessionId: String): Long = tracker.currentUsage(sessionId)
}
