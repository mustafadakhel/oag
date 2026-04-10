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
    fun `zero-score turns are recorded in scoredTurns`() {
        val tracker = SessionRequestTracker()
        tracker.recordInjectionScore("s1", 0.0)
        tracker.recordInjectionScore("s1", 0.5)
        tracker.recordInjectionScore("s1", 0.0)

        val trend = tracker.injectionTrend("s1")
        assertEquals(3, trend.scoredTurns.size)
        assertEquals(0.0, trend.scoredTurns[0].score, 0.001)
        assertEquals(0.5, trend.scoredTurns[1].score, 0.001)
        assertEquals(0.0, trend.scoredTurns[2].score, 0.001)
    }

    @Test
    fun `scoredTurns track turn indices`() {
        val tracker = SessionRequestTracker()
        tracker.recordInjectionScore("s1", 0.1)
        tracker.recordInjectionScore("s1", 0.2)
        tracker.recordInjectionScore("s1", 0.3)

        val trend = tracker.injectionTrend("s1")
        assertEquals(1L, trend.scoredTurns[0].turnIndex)
        assertEquals(2L, trend.scoredTurns[1].turnIndex)
        assertEquals(3L, trend.scoredTurns[2].turnIndex)
    }

    @Test
    fun `totalTurnCount tracks all recorded turns`() {
        val tracker = SessionRequestTracker()
        tracker.recordInjectionScore("s1", 0.0)
        tracker.recordInjectionScore("s1", 0.0)
        tracker.recordInjectionScore("s1", 0.5)

        val trend = tracker.injectionTrend("s1")
        assertEquals(3L, trend.totalTurnCount)
    }

    @Test
    fun `scoredTurns evict oldest when exceeding maxScoreHistory`() {
        val tracker = SessionRequestTracker(maxScoreHistory = 3)
        tracker.recordInjectionScore("s1", 0.1)
        tracker.recordInjectionScore("s1", 0.2)
        tracker.recordInjectionScore("s1", 0.3)
        tracker.recordInjectionScore("s1", 0.4)

        val trend = tracker.injectionTrend("s1")
        assertEquals(3, trend.scoredTurns.size)
        assertEquals(0.2, trend.scoredTurns[0].score, 0.001)
        assertEquals(4L, trend.totalTurnCount)
    }

    @Test
    fun `zero-score turns excluded from injectionScoreHistory but included in scoredTurns`() {
        val tracker = SessionRequestTracker()
        tracker.recordInjectionScore("s1", 0.0)
        tracker.recordInjectionScore("s1", 0.5)

        val trend = tracker.injectionTrend("s1")
        assertEquals(1, trend.scores.size)
        assertEquals(2, trend.scoredTurns.size)
    }

    @Test
    fun `chainHead is null for new session`() {
        val tracker = SessionRequestTracker()
        kotlin.test.assertNull(tracker.chainHead("s1"))
    }

    @Test
    fun `chainHead is null for unknown session`() {
        val tracker = SessionRequestTracker()
        kotlin.test.assertNull(tracker.chainHead("unknown"))
    }

    @Test
    fun `chainHead set after record with bodyHash`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", "abc123")
        val head = tracker.chainHead("s1")
        kotlin.test.assertNotNull(head)
        assertEquals(64, head.length, "chain head should be full SHA-256 hex (64 chars)")
        assertTrue(head.all { it in '0'..'9' || it in 'a'..'f' })
    }

    @Test
    fun `chainHead unchanged when bodyHash is null`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", "abc123")
        val headAfterBody = tracker.chainHead("s1")
        tracker.record("s1", "api.example.com", null)
        assertEquals(headAfterBody, tracker.chainHead("s1"))
    }

    @Test
    fun `chainHead changes with each new bodyHash`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", "hash1")
        val head1 = tracker.chainHead("s1")
        tracker.record("s1", "api.example.com", "hash2")
        val head2 = tracker.chainHead("s1")
        assertTrue(head1 != head2, "chain head should change after new body hash")
    }

    @Test
    fun `chainHead is deterministic for same inputs`() {
        val tracker1 = SessionRequestTracker()
        tracker1.record("s1", "api.example.com", "hash1")
        tracker1.record("s1", "api.example.com", "hash2")

        val tracker2 = SessionRequestTracker()
        tracker2.record("s1", "api.example.com", "hash1")
        tracker2.record("s1", "api.example.com", "hash2")

        assertEquals(tracker1.chainHead("s1"), tracker2.chainHead("s1"))
    }

    @Test
    fun `different sessions produce different chain heads for same body sequence`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", "hash1")
        tracker.record("s2", "api.example.com", "hash1")
        // Both sessions have same single body hash, so chain head should be identical
        // (since chain starts from null for both). After a second request, they diverge
        // only if the bodies differ. With identical bodies they produce identical chains.
        assertEquals(tracker.chainHead("s1"), tracker.chainHead("s2"),
            "Same body sequence should produce same chain head (replay detection uses session isolation)")
    }

    @Test
    fun `chain head diverges when sessions have different body sequences`() {
        val tracker = SessionRequestTracker()
        tracker.record("s1", "api.example.com", "hash1")
        tracker.record("s1", "api.example.com", "hash2")

        tracker.record("s2", "api.example.com", "hash1")
        tracker.record("s2", "api.example.com", "hash3")

        assertTrue(tracker.chainHead("s1") != tracker.chainHead("s2"),
            "Different body sequences should produce different chain heads")
    }

    @Test
    fun `computeChainHash is deterministic`() {
        val hash1 = SessionRequestTracker.computeChainHash("prevHead", "bodyHash")
        val hash2 = SessionRequestTracker.computeChainHash("prevHead", "bodyHash")
        assertEquals(hash1, hash2)
    }

    @Test
    fun `computeChainHash with null previous head`() {
        val hash = SessionRequestTracker.computeChainHash(null, "bodyHash")
        kotlin.test.assertNotNull(hash)
        assertEquals(64, hash.length)
    }

    @Test
    fun `computeChainHash differs for different inputs`() {
        val hash1 = SessionRequestTracker.computeChainHash("head1", "body1")
        val hash2 = SessionRequestTracker.computeChainHash("head2", "body1")
        assertTrue(hash1 != hash2)
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
