package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.ConcurrentLruMap
import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.MS_PER_SECOND

import java.security.MessageDigest
import java.time.Clock

data class ClaimContradiction(
    val claimKey: String,
    val previousValue: String,
    val newValue: String
)

data class ScoredTurn(
    val turnIndex: Long,
    val score: Double
)

data class VelocitySnapshot(
    val sessionRequestsPerSecond: Double,
    val spikeDetected: Boolean
)

data class InjectionTrendSnapshot(
    val scores: List<Double>,
    val escalating: Boolean,
    val scoredTurns: List<ScoredTurn> = emptyList(),
    val totalTurnCount: Long = 0
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
    private val maxClaimHistory: Int = DEFAULT_MAX_CLAIM_HISTORY,
    private val maxToolExcerpts: Int = DEFAULT_MAX_TOOL_EXCERPTS,
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
            state.chainHead = computeChainHash(state.chainHead, bodyHash)
        }
        state.requestTimestamps.add(nowMs)
        state.hostTimestamps.getOrPut(host) { ArrayDeque() }.add(nowMs)
        pruneTimestamps(state, nowMs)
    }

    fun recordInjectionScore(sessionId: String, score: Double) {
        sessions.withLock {
            val state = getOrPut(sessionId) { SessionState() }
            state.totalTurnCount++
            state.scoredTurns.add(ScoredTurn(turnIndex = state.totalTurnCount, score = score))
            if (state.scoredTurns.size > maxScoreHistory) {
                state.scoredTurns.removeFirst()
            }
            if (score > 0.0) {
                state.injectionScoreHistory.add(score)
                if (state.injectionScoreHistory.size > maxScoreHistory) {
                    state.injectionScoreHistory.removeFirst()
                }
            }
        }
    }

    fun injectionTrend(sessionId: String): InjectionTrendSnapshot = sessions.withLock {
        val state = this[sessionId]
            ?: return@withLock InjectionTrendSnapshot(scores = emptyList(), escalating = false)
        val scores = state.injectionScoreHistory.toList()
        val escalating = detectEscalation(scores)
        InjectionTrendSnapshot(
            scores = scores,
            escalating = escalating,
            scoredTurns = state.scoredTurns.toList(),
            totalTurnCount = state.totalTurnCount
        )
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

    fun recordClaims(sessionId: String, responseText: String, trusted: Boolean = true) = sessions.withLock {
        val state = getOrPut(sessionId) { SessionState() }
        if (!trusted) return@withLock
        val claims = extractClaimFingerprints(responseText)
        for ((key, value) in claims) {
            state.claimFingerprints[key] = value
        }
        if (state.claimFingerprints.size > maxClaimHistory) {
            val keysToRemove = state.claimFingerprints.keys.take(state.claimFingerprints.size - maxClaimHistory)
            keysToRemove.forEach { state.claimFingerprints.remove(it) }
        }
    }

    fun detectContradictions(sessionId: String, responseText: String): List<ClaimContradiction> = sessions.withLock {
        val state = this[sessionId]
            ?: return@withLock emptyList()
        val newClaims = extractClaimFingerprints(responseText)
        buildList {
            for ((key, newValue) in newClaims) {
                val existingValue = state.claimFingerprints[key] ?: continue
                if (existingValue != newValue) {
                    add(ClaimContradiction(key, existingValue, newValue))
                }
            }
        }
    }

    fun recordToolResponse(sessionId: String, requestKey: String, excerpt: String) = sessions.withLock {
        val state = getOrPut(sessionId) { SessionState() }
        state.toolResponseExcerpts[requestKey] = excerpt.take(MAX_EXCERPT_LENGTH)
        if (state.toolResponseExcerpts.size > maxToolExcerpts) {
            val keysToRemove = state.toolResponseExcerpts.keys.take(state.toolResponseExcerpts.size - maxToolExcerpts)
            keysToRemove.forEach { state.toolResponseExcerpts.remove(it) }
        }
    }

    fun getToolExcerpts(sessionId: String): Map<String, String> = sessions.withLock {
        val state = this[sessionId] ?: return@withLock emptyMap()
        state.toolResponseExcerpts.toMap()
    }

    fun chainHead(sessionId: String): String? = sessions.withLock {
        this[sessionId]?.chainHead
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
        val scoredTurns = ArrayDeque<ScoredTurn>()
        var totalTurnCount: Long = 0
        val requestTimestamps = ArrayDeque<Long>()
        val hostTimestamps = mutableMapOf<String, ArrayDeque<Long>>()
        val claimFingerprints = mutableMapOf<String, String>()
        val toolResponseExcerpts = mutableMapOf<String, String>()
        var chainHead: String? = null
    }

    companion object {
        private const val DEFAULT_MAX_BODY_HASH_HISTORY = 64
        private const val DEFAULT_MAX_SCORE_HISTORY = 64
        private const val DEFAULT_VELOCITY_WINDOW_MS = 60_000L
        private const val DEFAULT_MAX_CLAIM_HISTORY = 256
        private const val DEFAULT_MAX_TOOL_EXCERPTS = 64
        private const val MAX_EXCERPT_LENGTH = 512

        private const val BODY_HASH_PREFIX_LENGTH = 16

        fun bodyHash(body: ByteArray): String {
            val digest = MessageDigest.getInstance(CryptoConstants.SHA_256)
            val hash = digest.digest(body)
            return hash.toHexString().take(BODY_HASH_PREFIX_LENGTH)
        }

        internal fun computeChainHash(previousChainHead: String?, bodyHash: String): String {
            val input = (previousChainHead.orEmpty() + bodyHash).toByteArray(Charsets.UTF_8)
            val digest = MessageDigest.getInstance(CryptoConstants.SHA_256)
            return digest.digest(input).toHexString()
        }
    }
}

private val URL_CLAIM_PATTERN = Regex("""(https?://[^\s<>"']+)""")
private val VERSION_CLAIM_PATTERN = Regex("""(\w+(?:\.\w+)*)\s+(?:v(?:ersion)?\s*)?(\d+(?:\.\d+)+)""")
private val NUMERIC_ASSERTION_PATTERN = Regex("""(?:is|are|was|were|equals?|approximately|about)\s+(\d+(?:[.,]\d+)?)""")

internal fun extractClaimFingerprints(text: String): Map<String, String> {
    val claims = mutableMapOf<String, String>()

    URL_CLAIM_PATTERN.findAll(text).take(MAX_CLAIMS_PER_TEXT).forEach { match ->
        val url = match.groupValues[1].trimEnd('.', ',', ')', ']')
        claims["url:$url"] = url
    }

    VERSION_CLAIM_PATTERN.findAll(text).take(MAX_CLAIMS_PER_TEXT).forEach { match ->
        val name = match.groupValues[1].lowercase()
        val version = match.groupValues[2]
        claims["version:$name"] = version
    }

    NUMERIC_ASSERTION_PATTERN.findAll(text).take(MAX_CLAIMS_PER_TEXT).forEach { match ->
        val context = text.substring(
            maxOf(0, match.range.first - ASSERTION_CONTEXT_CHARS),
            minOf(text.length, match.range.last + 1)
        ).trim().lowercase()
        val value = match.groupValues[1]
        claims["numeric:$context"] = value
    }

    return claims
}

private const val MAX_CLAIMS_PER_TEXT = 50
private const val ASSERTION_CONTEXT_CHARS = 30
