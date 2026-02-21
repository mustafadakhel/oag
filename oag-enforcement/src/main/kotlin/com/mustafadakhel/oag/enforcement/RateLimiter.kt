package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.ConcurrentLruMap
import com.mustafadakhel.oag.RateLimitConfig

private const val NANOS_PER_SECOND = 1_000_000_000.0

class TokenBucket(
    private val requestsPerSecond: Double,
    private val burst: Int,
    private val nanoTimeSource: () -> Long = System::nanoTime
) {
    private val lock = Any()
    private var tokens: Double = burst.toDouble()
    private var lastRefillNanos: Long = nanoTimeSource()

    fun tryAcquire(): Boolean = synchronized(lock) {
        refill()
        if (tokens >= 1.0) {
            tokens -= 1.0
            true
        } else {
            false
        }
    }

    private fun refill() {
        val now = nanoTimeSource()
        val elapsedSeconds = (now - lastRefillNanos) / NANOS_PER_SECOND
        tokens = (tokens + elapsedSeconds * requestsPerSecond).coerceAtMost(burst.toDouble())
        lastRefillNanos = now
    }
}

class RateLimiterRegistry(private val maxEntries: Int = DEFAULT_MAX_LRU_ENTRIES) {
    private val buckets = ConcurrentLruMap<String, TokenBucket>(maxEntries)

    fun configure(ruleId: String, requestsPerSecond: Double, burst: Int) =
        buckets.put(ruleId, TokenBucket(requestsPerSecond, burst))

    fun tryAcquire(ruleId: String): Boolean =
        buckets.get(ruleId)?.tryAcquire() ?: false

    fun getOrCreateAndAcquire(key: String, requestsPerMinute: Int): Boolean =
        buckets.getOrPut(key) {
            TokenBucket(requestsPerMinute / 60.0, requestsPerMinute.coerceAtLeast(1))
        }.tryAcquire()

    fun replaceAll(configs: List<RateLimitConfig>) = buckets.withLock {
        clear()
        configs.forEach { (ruleId, rps, burst) -> this[ruleId] = TokenBucket(rps, burst) }
    }

    fun clear() = buckets.clear()
}
