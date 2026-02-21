package com.mustafadakhel.oag.inspection.injection

import com.mustafadakhel.oag.LOG_PREFIX

enum class MlTriggerMode {
    ALWAYS,
    UNCERTAIN_ONLY
}

class CombinedInjectionClassifier(
    private val heuristic: InjectionClassifier,
    private val ml: InjectionClassifier?,
    private val mlTriggerMode: MlTriggerMode = MlTriggerMode.ALWAYS,
    private val uncertainLow: Double = DEFAULT_UNCERTAIN_LOW,
    private val uncertainHigh: Double = DEFAULT_UNCERTAIN_HIGH,
    private val onError: (String) -> Unit = System.err::println
) : InjectionClassifier, AutoCloseable {
    init {
        require(uncertainLow <= uncertainHigh) { "uncertainLow ($uncertainLow) must be <= uncertainHigh ($uncertainHigh)" }
    }

    override fun classify(content: String): ClassificationResult {
        val heuristicResult = heuristic.classify(content)

        val mlClassifier = ml ?: return heuristicResult

        val shouldRunMl = when (mlTriggerMode) {
            MlTriggerMode.ALWAYS -> true
            MlTriggerMode.UNCERTAIN_ONLY ->
                heuristicResult.score in uncertainLow..uncertainHigh
        }

        if (!shouldRunMl) return heuristicResult

        val mlResult = runCatching { mlClassifier.classify(content) }
            .onFailure { e -> onError("$ERROR_PREFIX$ML_CLASSIFY_FAILED${e.message}") }
            .getOrNull() ?: return heuristicResult

        val combinedScore = maxOf(heuristicResult.score, mlResult.score)
        val combinedSignals = heuristicResult.signals + mlResult.signals

        return ClassificationResult(
            score = combinedScore,
            signals = combinedSignals,
            source = SOURCE
        )
    }

    override fun close() {
        (heuristic as? AutoCloseable)?.let { closeable ->
            runCatching { closeable.close() }.onFailure { e ->
                onError("$ERROR_PREFIX$HEURISTIC_CLOSE_FAILED${e.message}")
            }
        }
        (ml as? AutoCloseable)?.let { closeable ->
            runCatching { closeable.close() }.onFailure { e ->
                onError("$ERROR_PREFIX$ML_CLOSE_FAILED${e.message}")
            }
        }
    }

    companion object {
        const val SOURCE = "combined"
        const val DEFAULT_UNCERTAIN_LOW = 0.3
        const val DEFAULT_UNCERTAIN_HIGH = 0.8
        internal const val ERROR_PREFIX = LOG_PREFIX
        internal const val HEURISTIC_CLOSE_FAILED = "heuristic classifier close failed: "
        internal const val ML_CLOSE_FAILED = "ml classifier close failed: "
        internal const val ML_CLASSIFY_FAILED = "ml classifier failed: "
    }
}
