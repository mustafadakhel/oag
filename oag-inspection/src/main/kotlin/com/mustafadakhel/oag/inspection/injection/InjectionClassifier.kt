package com.mustafadakhel.oag.inspection.injection

import com.mustafadakhel.oag.label

data class ClassificationResult(
    val score: Double,
    val signals: List<String>,
    val source: String
)

fun interface InjectionClassifier {
    fun classify(content: String): ClassificationResult
}

class HeuristicInjectionClassifier(
    private val scorer: HeuristicScorer = HeuristicScorer()
) : InjectionClassifier {

    override fun classify(content: String): ClassificationResult {
        val result = scorer.score(content)
        val signals = result.signals.flatMap { s ->
            s.patterns.map { "${s.category.label()}:$it" }
        }
        return ClassificationResult(
            score = result.score,
            signals = signals,
            source = SOURCE
        )
    }

    companion object {
        const val SOURCE = "heuristic"
    }
}
