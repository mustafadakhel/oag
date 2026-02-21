package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.ConcurrentLruMap
import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.MS_PER_SECOND

import java.security.MessageDigest
import java.time.Clock

data class VelocitySnapshot(
    val sessionRequestsPerSecond: Double,
    val spikeDetected: Boolean
)

data class InjectionTrendSnapshot(
    val scores: List<Double>,
    val escalating: Boolean
)

private fun detectEscalation(scores: List<Double>): Boolean {
    if (scores.size < 3) return false
    val recent = scores.takeLast(3)
    return recent.zipWithNext().all { (a, b) -> b > a }
}

class SessionRequestTracker(
    private val maxBodyHashHistory: Int = DEFAULT_MAX_BODY_HASH_HISTORY,
    private val maxScoreHistory: Int = DEFAULT_MAX_SCORE_HISTORY,
    private val velocityWindowMs: Long = DEFAULT_VELOCITY_WINDOW_MS,
    private val maxSessions: Int = DEFAULT_MAX_LRU_ENTRIES,
    private val clock: Clock = Clock.systemUTC()
) {
    private val sessions = ConcurrentLruMap<String, SessionState>(maxSessions)

    fun record(sessionId: String, host: String, bodyHash: String?) = sessions.withLock {
        val state = getOrPut(sessionId) { SessionState() }
        val nowMs = clock.millis()
        if (bodyHash != null) {
            state.bodyHashes.add(bodyHash)
            if (state.bodyHashes.size > maxBodyHashHistory) {
                state.bodyHashes.removeFirst()
            }
        }
        state.requestTimestamps.add(nowMs)
        state.hostTimestamps.getOrPut(host) { ArrayDeque() }.add(nowMs)
        pruneTimestamps(state, nowMs)
    }

    fun recordInjectionScore(sessionId: String, score: Double) {
        if (score <= 0.0) return
        sessions.withLock {
            val state = getOrPut(sessionId) { SessionState() }
            state.injectionScoreHistory.add(score)
            if (state.injectionScoreHistory.size > maxScoreHistory) {
                state.injectionScoreHistory.removeFirst()
            }
        }
    }

    fun injectionTrend(sessionId: String): InjectionTrendSnapshot = sessions.withLock {
        val state = this[sessionId]
            ?: return@withLock InjectionTrendSnapshot(scores = emptyList(), escalating = false)
        val scores = state.injectionScoreHistory.toList()
        val escalating = detectEscalation(scores)
        InjectionTrendSnapshot(scores = scores, escalating = escalating)
    }

    fun velocity(sessionId: String, spikeThreshold: Double = Double.MAX_VALUE): VelocitySnapshot = sessions.withLock {
        val state = this[sessionId]
            ?: return@withLock VelocitySnapshot(0.0, false)
        val nowMs = clock.millis()
        pruneTimestamps(state, nowMs)
        val windowSeconds = velocityWindowMs / MS_PER_SECOND.toDouble()
        val sessionRps = state.requestTimestamps.size / windowSeconds
        val hostSpike = state.hostTimestamps.any { (_, ts) -> ts.size / windowSeconds >= spikeThreshold }
        VelocitySnapshot(
            sessionRequestsPerSecond = sessionRps,
            spikeDetected = sessionRps >= spikeThreshold || hostSpike
        )
    }

    fun clear() = sessions.clear()

    private fun pruneTimestamps(state: SessionState, nowMs: Long) {
        val cutoff = nowMs - velocityWindowMs
        while (state.requestTimestamps.isNotEmpty() && state.requestTimestamps.first() < cutoff) {
            state.requestTimestamps.removeFirst()
        }
        val iter = state.hostTimestamps.iterator()
        while (iter.hasNext()) {
            val (_, timestamps) = iter.next()
            while (timestamps.isNotEmpty() && timestamps.first() < cutoff) {
                timestamps.removeFirst()
            }
            if (timestamps.isEmpty()) iter.remove()
        }
    }

    private class SessionState {
        val bodyHashes = ArrayDeque<String>()
        val injectionScoreHistory = ArrayDeque<Double>()
        val requestTimestamps = ArrayDeque<Long>()
        val hostTimestamps = mutableMapOf<String, ArrayDeque<Long>>()
    }

    companion object {
        private const val DEFAULT_MAX_BODY_HASH_HISTORY = 64
        private const val DEFAULT_MAX_SCORE_HISTORY = 64
        private const val DEFAULT_VELOCITY_WINDOW_MS = 60_000L

        private const val BODY_HASH_PREFIX_LENGTH = 16

        fun bodyHash(body: ByteArray): String {
            val digest = MessageDigest.getInstance(CryptoConstants.SHA_256)
            val hash = digest.digest(body)
            return hash.toHexString().take(BODY_HASH_PREFIX_LENGTH)
        }
    }
}
