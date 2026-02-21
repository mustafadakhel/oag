package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.normalizeContent
import com.mustafadakhel.oag.policy.core.InjectionScoringMode
import com.mustafadakhel.oag.policy.core.PatternAnchor
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyInjectionScoring
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.inspection.injection.CategoryWeight
import com.mustafadakhel.oag.inspection.injection.HeuristicScorer
import com.mustafadakhel.oag.inspection.injection.InjectionClassifier
import com.mustafadakhel.oag.inspection.injection.InjectionPatterns
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.DEFAULT_DENY_THRESHOLD
import com.mustafadakhel.oag.pipeline.START_OF_MESSAGE_CHAR_LIMIT

internal val defaultInspectionErrorHandler: (String) -> Unit = { msg -> System.err.println("${LOG_PREFIX}$msg") }

// Fail-closed: regex compilation failure assumes threat (returns true → deny).
// This is intentional — contrast with PolicyMatchers.matchesBody which fail-opens (returns false → no match).
private fun regexMatchOrFailClosed(
    pattern: String,
    options: Set<RegexOption> = emptySet(),
    input: String,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): Boolean =
    runCatching { cachedRegex(pattern, options).containsMatchIn(input) }
        .onFailure { e -> onError("regex compilation failed pattern=$pattern: ${e.message}") }
        .getOrDefault(true)

fun checkContentInspection(
    body: String,
    inspection: PolicyContentInspection,
    policyService: PolicyService,
    mlClassifier: InjectionClassifier? = null,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): ContentInspectionResult {
    val scoringConfig = policyService.current.defaults?.injectionScoring
    if (scoringConfig?.mode == InjectionScoringMode.SCORE) {
        return checkContentInspectionScored(body, inspection, scoringConfig, mlClassifier, onError)
    }
    return checkContentInspectionBinary(body, inspection, onError)
}

fun matchCustomAndAnchoredPatterns(
    inspection: PolicyContentInspection,
    normalized: String,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): List<String> = buildList {
    if (!inspection.customPatterns.isNullOrEmpty()) {
        for (pattern in inspection.customPatterns) {
            val hit = regexMatchOrFailClosed(pattern, setOf(RegexOption.IGNORE_CASE), normalized, onError)
            if (hit) add("custom:$pattern")
        }
    }
    if (!inspection.anchoredPatterns.isNullOrEmpty()) {
        for (ap in inspection.anchoredPatterns) {
            val anchor = ap.anchor ?: PatternAnchor.ANY
            val hit = matchAnchoredPattern(ap.pattern, anchor, normalized, onError)
            if (hit) add("anchored:${anchor.label()}:${ap.pattern}")
        }
    }
}

fun checkContentInspectionBinary(
    body: String,
    inspection: PolicyContentInspection,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): ContentInspectionResult {
    val normalized = body.normalizeContent()
    val allMatched = buildList {
        if (inspection.enableBuiltinPatterns == true) {
            addAll(InjectionPatterns.matches(normalized))
        }
        addAll(matchCustomAndAnchoredPatterns(inspection, normalized, onError))
    }

    val decision = allMatched.takeIf { it.isNotEmpty() }?.let {
        PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.INJECTION_DETECTED)
    }

    return ContentInspectionResult(decision, allMatched)
}

fun checkContentInspectionScored(
    body: String,
    inspection: PolicyContentInspection,
    scoringConfig: PolicyInjectionScoring,
    mlClassifier: InjectionClassifier? = null,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): ContentInspectionResult {
    val normalized = body.normalizeContent()

    val categoryWeights = buildScorerCategoryWeights(scoringConfig)
    val scorer = HeuristicScorer(
        categoryWeights = categoryWeights,
        entropyWeight = scoringConfig.entropyWeight ?: HeuristicScorer.DEFAULT_ENTROPY_WEIGHT,
        entropyBaseline = scoringConfig.entropyBaseline ?: HeuristicScorer.DEFAULT_ENTROPY_BASELINE
    )
    val scoreResult = scorer.score(normalized)

    val allMatched = buildList {
        addAll(matchCustomAndAnchoredPatterns(inspection, normalized, onError))
        for (signal in scoreResult.signals) {
            addAll(signal.patterns)
        }
    }

    val mlResult = mlClassifier?.let { ml ->
        runCatching { ml.classify(normalized) }.getOrNull()
    }

    val effectiveScore = if (mlResult != null) maxOf(scoreResult.score, mlResult.score) else scoreResult.score
    val signals = buildList {
        addAll(scoreResult.signals.flatMap { signal -> signal.patterns.map { "${signal.category.label()}:$it" } })
        if (mlResult != null) addAll(mlResult.signals)
    }

    val denyThreshold = scoringConfig.denyThreshold ?: DEFAULT_DENY_THRESHOLD
    val logThreshold = scoringConfig.logThreshold
    val exceedsDeny = effectiveScore >= denyThreshold || allMatched.any { it.startsWith("custom:") || it.startsWith("anchored:") }
    val exceedsLog = logThreshold != null && effectiveScore >= logThreshold

    val decision = if (exceedsDeny) {
        PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.INJECTION_DETECTED)
    } else null

    return ContentInspectionResult(
        decision = decision,
        matchedPatterns = if (exceedsDeny || exceedsLog) allMatched else emptyList(),
        injectionScore = effectiveScore,
        injectionSignals = if (exceedsDeny || exceedsLog) signals else emptyList()
    )
}

private fun buildScorerCategoryWeights(config: PolicyInjectionScoring): List<CategoryWeight> {
    val defaults = HeuristicScorer.defaultCategoryWeights()
    val overrides = config.categoryWeights?.associate { it.category to it.weight } ?: emptyMap()
    return defaults.map { cw ->
        overrides[cw.category.label()]?.let { cw.copy(weight = it) } ?: cw
    }
}

fun matchAnchoredPattern(
    pattern: String,
    anchor: PatternAnchor,
    normalized: String,
    onError: (String) -> Unit = defaultInspectionErrorHandler
): Boolean =
    when (anchor) {
        PatternAnchor.ANY ->
            regexMatchOrFailClosed(pattern, setOf(RegexOption.IGNORE_CASE), normalized, onError)
        PatternAnchor.START_OF_MESSAGE ->
            regexMatchOrFailClosed(pattern, setOf(RegexOption.IGNORE_CASE), normalized.take(START_OF_MESSAGE_CHAR_LIMIT), onError)
        PatternAnchor.STANDALONE ->
            regexMatchOrFailClosed(
                "^\\s*(?:${pattern})\\s*$",
                setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE),
                normalized,
                onError
            )
    }
