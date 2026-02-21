package com.mustafadakhel.oag

import kotlinx.coroutines.test.runTest

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class RetryTest {

    @Test
    fun `succeeds on first attempt`() {
        val result = withRetry(RetryPolicy(maxAttempts = 3)) { "ok" }
        assertEquals("ok", result)
    }

    @Test
    fun `succeeds after retries`() {
        var calls = 0
        val result = withRetry(RetryPolicy(maxAttempts = 3, baseDelayMs = 1)) {
            calls++
            if (calls < 3) error("fail")
            "ok"
        }
        assertEquals("ok", result)
        assertEquals(3, calls)
    }

    @Test
    fun `throws RetryExhaustedException when all attempts fail`() {
        val ex = assertFailsWith<RetryExhaustedException> {
            withRetry(RetryPolicy(maxAttempts = 2, baseDelayMs = 1)) {
                error("boom")
            }
        }
        assertEquals(2, ex.attempts)
        assertIs<IllegalStateException>(ex.lastError)
        assertEquals("boom", ex.lastError.message)
    }

    @Test
    fun `onFailure called for each failed attempt`() {
        val failures = mutableListOf<Int>()
        assertFailsWith<RetryExhaustedException> {
            withRetry(
                RetryPolicy(maxAttempts = 3, baseDelayMs = 1),
                onFailure = { attempt, _ -> failures.add(attempt) }
            ) {
                error("fail")
            }
        }
        assertEquals(listOf(1, 2, 3), failures)
    }

    @Test
    fun `onFailure not called on success`() {
        var failureCalled = false
        withRetry(
            RetryPolicy(maxAttempts = 3),
            onFailure = { _, _ -> failureCalled = true }
        ) { "ok" }
        assertTrue(!failureCalled)
    }

    @Test
    fun `exponential backoff increases delay`() {
        val delays = mutableListOf<Long>()
        val start = System.currentTimeMillis()
        var lastTimestamp = start
        assertFailsWith<RetryExhaustedException> {
            withRetry(
                RetryPolicy(maxAttempts = 4, baseDelayMs = 50, multiplier = 2.0),
                onFailure = { attempt, _ ->
                    if (attempt > 1) {
                        val now = System.currentTimeMillis()
                        delays.add(now - lastTimestamp)
                        lastTimestamp = now
                    } else {
                        lastTimestamp = System.currentTimeMillis()
                    }
                }
            ) {
                error("fail")
            }
        }
        // delays should be roughly [50, 100, 200] but with timing jitter
        assertEquals(3, delays.size)
        assertTrue(delays[0] >= 30, "first delay should be ~50ms, was ${delays[0]}")
        assertTrue(delays[1] >= 70, "second delay should be ~100ms, was ${delays[1]}")
        assertTrue(delays[2] >= 140, "third delay should be ~200ms, was ${delays[2]}")
    }

    @Test
    fun `maxDelayMs caps backoff`() {
        val delays = mutableListOf<Long>()
        var lastTimestamp = 0L
        assertFailsWith<RetryExhaustedException> {
            withRetry(
                RetryPolicy(maxAttempts = 4, baseDelayMs = 50, maxDelayMs = 60, multiplier = 2.0),
                onFailure = { attempt, _ ->
                    val now = System.currentTimeMillis()
                    if (attempt > 1) delays.add(now - lastTimestamp)
                    lastTimestamp = now
                }
            ) {
                error("fail")
            }
        }
        assertEquals(3, delays.size)
        // After first delay (50ms), next would be 100ms but capped to 60ms
        assertTrue(delays[1] < 100, "second delay should be capped at ~60ms, was ${delays[1]}")
    }

    @Test
    fun `single attempt throws immediately without sleeping`() {
        val start = System.currentTimeMillis()
        assertFailsWith<RetryExhaustedException> {
            withRetry(RetryPolicy(maxAttempts = 1, baseDelayMs = 10_000)) {
                error("fail")
            }
        }
        val elapsed = System.currentTimeMillis() - start
        assertTrue(elapsed < 1_000, "single attempt should not sleep, elapsed=$elapsed")
    }

    @Test
    fun `RetryPolicy defaults`() {
        val policy = RetryPolicy()
        assertEquals(3, policy.maxAttempts)
        assertEquals(500L, policy.baseDelayMs)
        assertEquals(Long.MAX_VALUE, policy.maxDelayMs)
        assertEquals(2.0, policy.multiplier)
    }

    @Test
    fun `withSuspendRetry succeeds on first attempt`() = runTest {
        val result = withSuspendRetry(RetryPolicy(maxAttempts = 3)) { "ok" }
        assertEquals("ok", result)
    }

    @Test
    fun `withSuspendRetry succeeds after retries`() = runTest {
        var calls = 0
        val result = withSuspendRetry(RetryPolicy(maxAttempts = 3, baseDelayMs = 100)) {
            calls++
            if (calls < 3) error("fail")
            "ok"
        }
        assertEquals("ok", result)
        assertEquals(3, calls)
    }

    @Test
    fun `withSuspendRetry throws RetryExhaustedException when all attempts fail`() = runTest {
        val ex = assertFailsWith<RetryExhaustedException> {
            withSuspendRetry(RetryPolicy(maxAttempts = 2, baseDelayMs = 100)) {
                error("boom")
            }
        }
        assertEquals(2, ex.attempts)
        assertIs<IllegalStateException>(ex.lastError)
    }

    @Test
    fun `withSuspendRetry calls onFailure for each failed attempt`() = runTest {
        val failures = mutableListOf<Int>()
        assertFailsWith<RetryExhaustedException> {
            withSuspendRetry(
                RetryPolicy(maxAttempts = 3, baseDelayMs = 100),
                onFailure = { attempt, _ -> failures.add(attempt) }
            ) {
                error("fail")
            }
        }
        assertEquals(listOf(1, 2, 3), failures)
    }
}
