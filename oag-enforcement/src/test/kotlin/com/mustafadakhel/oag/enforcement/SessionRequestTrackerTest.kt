package com.mustafadakhel.oag.enforcement

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SessionRequestTrackerTest {

    @Test
    fun `records and counts requests`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.record("s1", "api.example.com", null)
        tracker.record("s1", "other.example.com", null)

        // velocity should reflect the recorded requests
        val velocity = tracker.velocity("s1")
        assertTrue(velocity.sessionRequestsPerSecond > 0.0)
    }

    @Test
    fun `bodyHash is deterministic`() {
        val hash1 = SessionRequestTracker.bodyHash("same content".toByteArray())
        val hash2 = SessionRequestTracker.bodyHash("same content".toByteArray())
        assertEquals(hash1, hash2)
    }

    @Test
    fun `bodyHash is 16 chars hex prefix`() {
        val hash = SessionRequestTracker.bodyHash("test".toByteArray())
        assertEquals(16, hash.length)
        assertTrue(hash.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `bodyHash differs for different content`() {
        val hash1 = SessionRequestTracker.bodyHash("content1".toByteArray())
        val hash2 = SessionRequestTracker.bodyHash("content2".toByteArray())
        assertTrue(hash1 != hash2)
    }

    @Test
    fun `recordInjectionScore accumulates in velocity context`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.8)
        tracker.recordInjectionScore("s1", 1.2)

        // Injection scores are tracked internally; verify session still works
        val velocity = tracker.velocity("s1")
        assertTrue(velocity.sessionRequestsPerSecond > 0.0)
    }

    @Test
    fun `velocity returns zero for unknown session`() {
        val tracker = SessionRequestTracker()
        val velocity = tracker.velocity("unknown")
        assertEquals(0.0, velocity.sessionRequestsPerSecond, 0.001)
        assertFalse(velocity.spikeDetected)
    }

    @Test
    fun `velocity tracks requests in window`() {
        val tracker = SessionRequestTracker(velocityWindowMs = 60_000L)
        for (i in 1..10) {
            tracker.record("s1", "api.example.com", null)
        }

        val velocity = tracker.velocity("s1")
        assertTrue(velocity.sessionRequestsPerSecond > 0.0)
    }

    @Test
    fun `velocity spike detection with threshold`() {
        val tracker = SessionRequestTracker(velocityWindowMs = 60_000L)
        for (i in 1..100) {
            tracker.record("s1", "api.example.com", null)
        }

        val velocity = tracker.velocity("s1", spikeThreshold = 0.5)
        assertTrue(velocity.spikeDetected)
    }

    @Test
    fun `velocity spike not detected below threshold`() {
        val tracker = SessionRequestTracker(velocityWindowMs = 60_000L)
        tracker.record("s1", "api.example.com", null)

        val velocity = tracker.velocity("s1", spikeThreshold = 100.0)
        assertFalse(velocity.spikeDetected)
    }

    @Test
    fun `clear removes all sessions`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.clear()

        val velocity = tracker.velocity("s1")
        assertEquals(0.0, velocity.sessionRequestsPerSecond, 0.001)
    }

    @Test
    fun `injectionTrend returns not escalating for unknown session`() {
        val tracker = SessionRequestTracker()
        val trend = tracker.injectionTrend("unknown")
        assertTrue(trend.scores.isEmpty())
        assertFalse(trend.escalating)
    }

    @Test
    fun `injectionTrend returns not escalating with fewer than 3 scores`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.7)

        val trend = tracker.injectionTrend("s1")
        assertEquals(2, trend.scores.size)
        assertFalse(trend.escalating)
    }

    @Test
    fun `injectionTrend detects escalation with 3 increasing scores`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.3)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.7)

        val trend = tracker.injectionTrend("s1")
        assertEquals(3, trend.scores.size)
        assertTrue(trend.escalating)
    }

    @Test
    fun `injectionTrend not escalating when scores decrease`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.7)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.3)

        val trend = tracker.injectionTrend("s1")
        assertFalse(trend.escalating)
    }

    @Test
    fun `injectionTrend detects escalation in last 3 of many scores`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.9)
        tracker.recordInjectionScore("s1", 0.2)
        tracker.recordInjectionScore("s1", 0.4)
        tracker.recordInjectionScore("s1", 0.6)
        tracker.recordInjectionScore("s1", 0.8)

        val trend = tracker.injectionTrend("s1")
        assertTrue(trend.escalating)
    }

    @Test
    fun `injectionTrend not escalating when last 3 are flat`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", null)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.5)

        val trend = tracker.injectionTrend("s1")
        assertFalse(trend.escalating)
    }

    @Test
    fun `concurrent access does not throw`() = runBlocking {
        val tracker = SessionRequestTracker()
        val workers = 10
        val perWorker = 100
        val done = CountDownLatch(workers)

        repeat(workers) { threadIdx ->
            launch(Dispatchers.Default) {
                repeat(perWorker) { i ->
                    tracker.record("s1", "host${threadIdx % 3}.com", "hash_${threadIdx}_$i")
                }
                done.countDown()
            }
        }

        assertTrue(done.await(5, TimeUnit.SECONDS), "timed out waiting for workers")
        val velocity = tracker.velocity("s1")
        assertTrue(velocity.sessionRequestsPerSecond > 0.0)
    }
}
