package com.mustafadakhel.oag.pipeline.relay

import kotlin.math.exp

data class LogprobAnalysis(
    val meanLogprob: Double,
    val minLogprob: Double,
    val tokenCount: Int,
    val score: Double
)

object LogprobAnalyzer {

    private val LOGPROB_VALUE_PATTERN = Regex(""""logprob"\s*:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)""")

    fun analyze(responseBody: String): LogprobAnalysis? {
        val logprobs = extractLogprobs(responseBody)
        if (logprobs.isEmpty()) return null

        val mean = logprobs.average()
        val min = logprobs.min()
        val score = mapToScore(mean)

        return LogprobAnalysis(
            meanLogprob = mean,
            minLogprob = min,
            tokenCount = logprobs.size,
            score = score
        )
    }

    internal fun extractLogprobs(responseBody: String): List<Double> =
        LOGPROB_VALUE_PATTERN.findAll(responseBody)
            .mapNotNull { it.groupValues[1].toDoubleOrNull() }
            .filter { it.isFinite() }
            .take(MAX_LOGPROBS)
            .toList()

    /**
     * Maps mean log-probability to a hallucination risk score in [0, 1].
     *
     * Log-probabilities are negative (or zero for certainty). More negative values
     * indicate lower model confidence. The mapping uses a sigmoid-like transformation:
     * - Mean logprob near 0 → score near 0 (high confidence, low risk)
     * - Mean logprob near -5 or below → score near 1 (low confidence, high risk)
     *
     * The formula: score = 1 - exp(meanLogprob / scale)
     * With scale=2.0: logprob -1 → 0.39, logprob -3 → 0.78, logprob -5 → 0.92
     */
    internal fun mapToScore(meanLogprob: Double): Double {
        if (meanLogprob >= 0.0) return 0.0
        return (1.0 - exp(meanLogprob / SCORE_SCALE)).coerceIn(0.0, 1.0)
    }

    private const val SCORE_SCALE = 2.0
    private const val MAX_LOGPROBS = 1000
}
