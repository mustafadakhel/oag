package com.mustafadakhel.oag.inspection.injection

import com.mustafadakhel.oag.inspection.PatternEntry
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.InjectionCategory
import com.mustafadakhel.oag.shannonEntropy

data class InjectionSignal(
    val category: InjectionCategory,
    val patterns: List<String>,
    val weight: Double,
    val contribution: Double
)

data class InjectionScore(
    val score: Double,
    val signals: List<InjectionSignal>,
    val entropyContribution: Double
)

data class CategoryWeight(
    val category: InjectionCategory,
    val patterns: List<PatternEntry>,
    val weight: Double
)

class HeuristicScorer(
    private val categoryWeights: List<CategoryWeight> = defaultCategoryWeights(),
    private val entropyWeight: Double = DEFAULT_ENTROPY_WEIGHT,
    private val entropyBaseline: Double = DEFAULT_ENTROPY_BASELINE,
    private val normalizationK: Double = DEFAULT_NORMALIZATION_K
) {
    fun score(content: String): InjectionScore {
        val signals = categoryWeights.mapNotNull { cw ->
            val matched = cw.patterns
                .filter { it.regex.containsMatchIn(content) }
                .map { it.name }
            matched.takeIf { it.isNotEmpty() }?.let {
                InjectionSignal(
                    category = cw.category,
                    patterns = it,
                    weight = cw.weight,
                    // Score contribution = category weight * number of matched patterns.
                    // Multiplicative boost: categories with many distinct matches contribute more.
                    contribution = cw.weight * it.size
                )
            }
        }

        val entropy = content.shannonEntropy()
        val entropyContribution = if (entropy > entropyBaseline) {
            (entropy - entropyBaseline) * entropyWeight
        } else {
            0.0
        }

        val rawScore = signals.sumOf { it.contribution } + entropyContribution
        val normalizedScore = rawScore / (rawScore + normalizationK)

        return InjectionScore(
            score = normalizedScore,
            signals = signals,
            entropyContribution = entropyContribution
        )
    }

    companion object {
        const val DEFAULT_ENTROPY_WEIGHT = 0.1
        const val DEFAULT_ENTROPY_BASELINE = 4.5
        const val DEFAULT_NORMALIZATION_K = 2.0

        fun defaultCategoryWeights(): List<CategoryWeight> = listOf(
            CategoryWeight(InjectionCategory.DELIMITER_INJECTION, InjectionPatterns.DELIMITER_INJECTION, 1.0),
            CategoryWeight(InjectionCategory.INSTRUCTION_OVERRIDE, InjectionPatterns.INSTRUCTION_OVERRIDE, 0.8),
            CategoryWeight(InjectionCategory.ROLE_ASSUMPTION, InjectionPatterns.ROLE_ASSUMPTION, 0.6),
            CategoryWeight(InjectionCategory.PROMPT_LEAKING, InjectionPatterns.PROMPT_LEAKING, 0.7),
            CategoryWeight(InjectionCategory.JAILBREAK, InjectionPatterns.JAILBREAK, 0.9),
            CategoryWeight(InjectionCategory.ENCODING_MARKERS, InjectionPatterns.ENCODING_MARKERS, 0.5),
        )
    }
}
