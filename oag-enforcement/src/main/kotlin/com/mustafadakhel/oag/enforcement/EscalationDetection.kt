/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.EscalationPattern


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
        if (matchesPattern(windowScores, pattern)) {
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

private fun matchesPattern(scores: List<Double>, pattern: EscalationPattern): Boolean = when (pattern) {
    EscalationPattern.SUSTAINED_ELEVATION -> detectSustainedElevation(scores)
    EscalationPattern.CRESCENDO -> detectCrescendo(scores)
}

private fun detectSustainedElevation(scores: List<Double>): Boolean {
    if (scores.size < 3) return false
    return scores.all { it > ELEVATION_THRESHOLD }
}

private fun detectCrescendo(scores: List<Double>): Boolean {
    if (scores.size < 3) return false
    return scores.zipWithNext().all { (a, b) -> b > a }
}

private const val ELEVATION_THRESHOLD = 0.3
