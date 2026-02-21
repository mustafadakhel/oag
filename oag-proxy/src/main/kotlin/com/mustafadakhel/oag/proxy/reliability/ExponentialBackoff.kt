package com.mustafadakhel.oag.proxy.reliability

import kotlin.math.pow
import kotlin.random.Random

import java.util.concurrent.atomic.AtomicInteger

/**
 * Stateful exponential backoff for ongoing health tracking (circuit breakers, policy watchers).
 * Tracks consecutive failures via [recordSuccess]/[recordFailure] — callers drive state transitions.
 *
 * Distinct from [com.mustafadakhel.oag.BackoffStrategy] (oag-core), which is a stateless fun
 * interface for retry loops where the caller tracks the attempt number. The different max defaults
 * reflect different use cases: retry loops should fail fast (30s), health tracking should be
 * patient (5min).
 */
class ExponentialBackoff(
    private val baseDelayMs: Long,
    private val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
    private val multiplier: Double = DEFAULT_MULTIPLIER,
    private val jitterFactor: Double = DEFAULT_JITTER_FACTOR,
    private val random: Random = Random.Default
) {
    private val consecutiveFailures = AtomicInteger(0)

    fun nextDelayMs(): Long {
        val failures = consecutiveFailures.get()
        if (failures == 0) return baseDelayMs
        val exponential = (baseDelayMs * multiplier.pow(failures.coerceAtMost(MAX_EXPONENT))).toLong()
        val capped = exponential.coerceAtMost(maxDelayMs)
        val jitter = (capped * jitterFactor * random.nextDouble()).toLong()
        return capped + jitter
    }

    fun recordSuccess() {
        consecutiveFailures.set(0)
    }

    fun recordFailure() {
        consecutiveFailures.incrementAndGet()
    }

    companion object {
        const val DEFAULT_MAX_DELAY_MS = 300_000L
        const val DEFAULT_MULTIPLIER = 2.0
        const val DEFAULT_JITTER_FACTOR = 0.1
        private const val MAX_EXPONENT = 20
    }
}
