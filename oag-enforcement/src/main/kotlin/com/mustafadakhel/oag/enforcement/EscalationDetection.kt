package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.EscalationPattern
import kotlin.math.sqrt


data class EscalationConfig(
    val enabled: Boolean = false,
    val windowSize: Int = DEFAULT_WINDOW_SIZE,
    val denyPatterns: Set<EscalationPattern> = emptySet()
) {
    companion object {
        const val DEFAULT_WINDOW_SIZE = 5
    }
}

data class EscalationResult(
    val detected: Boolean,
    val pattern: EscalationPattern? = null,
    val windowScores: List<Double> = emptyList(),
    val windowSize: Int = 0
)

fun detectEscalationPatterns(
    scoredTurns: List<ScoredTurn>,
    config: EscalationConfig
): EscalationResult {
    if (!config.enabled || scoredTurns.size < config.windowSize) {
        return EscalationResult(detected = false)
    }

    val window = scoredTurns.takeLast(config.windowSize)
    val windowScores = window.map { it.score }

    for (pattern in config.denyPatterns) {
        if (matchesPattern(window, pattern)) {
            return EscalationResult(
                detected = true,
                pattern = pattern,
                windowScores = windowScores,
                windowSize = config.windowSize
            )
        }
    }

    return EscalationResult(
        detected = false,
        windowScores = windowScores,
        windowSize = config.windowSize
    )
}

private fun matchesPattern(window: List<ScoredTurn>, pattern: EscalationPattern): Boolean = when (pattern) {
    EscalationPattern.SUSTAINED_ELEVATION -> detectSustainedElevation(window.map { it.score })
    EscalationPattern.CRESCENDO -> detectCrescendo(window.map { it.score })
    EscalationPattern.SAW_TOOTH_PROBING -> detectSawTooth(window.map { it.score })
    EscalationPattern.PERIODIC_TESTING -> detectPeriodicTesting(window)
}

private fun detectSustainedElevation(scores: List<Double>): Boolean {
    if (scores.size < MIN_WINDOW_FOR_DETECTION) return false
    return scores.all { it > ELEVATION_THRESHOLD }
}

private fun detectCrescendo(scores: List<Double>): Boolean {
    if (scores.size < MIN_WINDOW_FOR_DETECTION) return false
    return scores.zipWithNext().all { (a, b) -> b > a }
}

private fun detectSawTooth(scores: List<Double>): Boolean {
    if (scores.size < MIN_WINDOW_FOR_DETECTION) return false
    var transitions = 0
    var aboveCount = 0
    var previousAbove = scores.first() > ELEVATION_THRESHOLD
    if (previousAbove) aboveCount++

    for (i in 1 until scores.size) {
        val above = scores[i] > ELEVATION_THRESHOLD
        if (above) aboveCount++
        if (above != previousAbove) transitions++
        previousAbove = above
    }

    return transitions >= MIN_SAW_TOOTH_TRANSITIONS && aboveCount >= MIN_ABOVE_THRESHOLD_COUNT
}

private fun detectPeriodicTesting(turns: List<ScoredTurn>): Boolean {
    if (turns.size < MIN_WINDOW_FOR_DETECTION) return false
    val highTurns = turns.filter { it.score > ELEVATION_THRESHOLD }
    if (highTurns.size < MIN_PERIODIC_POINTS) return false

    val intervals = highTurns.zipWithNext { a, b -> (b.turnIndex - a.turnIndex).toDouble() }
    val meanInterval = intervals.sum() / intervals.size
    if (meanInterval < MIN_PERIODIC_INTERVAL) return false

    val variance = maxOf(intervals.sumOf { (it - meanInterval) * (it - meanInterval) } / intervals.size, 0.0)
    val cv = sqrt(variance) / meanInterval
    return cv <= MAX_PERIODIC_CV
}

private const val ELEVATION_THRESHOLD = 0.3
private const val MIN_WINDOW_FOR_DETECTION = 3
private const val MIN_SAW_TOOTH_TRANSITIONS = 2
private const val MIN_ABOVE_THRESHOLD_COUNT = 2
private const val MIN_PERIODIC_POINTS = 3
private const val MIN_PERIODIC_INTERVAL = 2.0
private const val MAX_PERIODIC_CV = 0.3
