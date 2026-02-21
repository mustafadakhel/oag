package com.mustafadakhel.oag.enforcement

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

class RateLimiterTest {
    @Test
    fun `token bucket allows burst requests immediately`() {
        val bucket = TokenBucket(requestsPerSecond = 10.0, burst = 3)

        assertTrue(bucket.tryAcquire())
        assertTrue(bucket.tryAcquire())
        assertTrue(bucket.tryAcquire())
        assertFalse(bucket.tryAcquire())
    }

    @Test
    fun `token bucket refills over time`() = runBlocking {
        val bucket = TokenBucket(requestsPerSecond = 1000.0, burst = 1)

        assertTrue(bucket.tryAcquire())
        assertFalse(bucket.tryAcquire())

        delay(10)
        assertTrue(bucket.tryAcquire())
    }

    @Test
    fun `registry denies unconfigured rule (fail-closed)`() {
        val registry = RateLimiterRegistry()
        assertFalse(registry.tryAcquire("unknown_rule"))
    }

    @Test
    fun `registry enforces configured rate limit`() {
        val registry = RateLimiterRegistry()
        registry.configure("rule1", requestsPerSecond = 10.0, burst = 2)

        assertTrue(registry.tryAcquire("rule1"))
        assertTrue(registry.tryAcquire("rule1"))
        assertFalse(registry.tryAcquire("rule1"))
    }

    @Test
    fun `registry isolates rate limits per rule`() {
        val registry = RateLimiterRegistry()
        registry.configure("rule_a", requestsPerSecond = 10.0, burst = 1)
        registry.configure("rule_b", requestsPerSecond = 10.0, burst = 1)

        assertTrue(registry.tryAcquire("rule_a"))
        assertFalse(registry.tryAcquire("rule_a"))
        assertTrue(registry.tryAcquire("rule_b"))
    }

    @Test
    fun `clear removes all configured buckets`() {
        val registry = RateLimiterRegistry()
        registry.configure("rule1", requestsPerSecond = 10.0, burst = 1)
        registry.tryAcquire("rule1")

        registry.clear()
        assertFalse(registry.tryAcquire("rule1"))
    }
}
