package com.mustafadakhel.oag.pipeline.network

import com.mustafadakhel.oag.inspection.content.PathAnalyzer
import com.mustafadakhel.oag.inspection.content.looksLikeBase64
import com.mustafadakhel.oag.inspection.content.maxSegmentEntropy
import com.mustafadakhel.oag.shannonEntropy
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyUrlInspection
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.pipeline.DEFAULT_ENTROPY_THRESHOLD
import com.mustafadakhel.oag.pipeline.DEFAULT_MIN_VALUE_LENGTH
import com.mustafadakhel.oag.pipeline.inspection.ExfiltrationCheckResult
import com.mustafadakhel.oag.pipeline.inspection.PathAnalysisResult

fun checkUrlExfiltration(path: String, defaults: PolicyDefaults?): ExfiltrationCheckResult {
    val inspection = defaults?.urlInspection ?: return ExfiltrationCheckResult(null)
    val queryIndex = path.indexOf('?')
    if (queryIndex < 0) return ExfiltrationCheckResult(null)
    val queryString = path.substring(queryIndex + 1)

    val maxQueryLength = inspection.maxQueryLength
    if (maxQueryLength != null && queryString.length > maxQueryLength) {
        return ExfiltrationCheckResult(PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.URL_EXFILTRATION_BLOCKED))
    }

    val minLen = inspection.minValueLength ?: DEFAULT_MIN_VALUE_LENGTH
    val entropyThreshold = inspection.entropyThreshold ?: DEFAULT_ENTROPY_THRESHOLD
    val denyDecision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.URL_EXFILTRATION_BLOCKED)
    var maxEntropy: Double? = null

    for (param in queryString.split('&')) {
        val eqIndex = param.indexOf('=')
        val value = if (eqIndex >= 0) param.substring(eqIndex + 1) else param
        if (value.length < minLen) continue

        val entropy = value.shannonEntropy()
        maxEntropy = maxOf(maxEntropy ?: 0.0, entropy)

        if (inspection.blockBase64Values == true && value.looksLikeBase64(minLen)) {
            return ExfiltrationCheckResult(denyDecision, maxEntropy)
        }
        if (entropy > entropyThreshold) {
            return ExfiltrationCheckResult(denyDecision, maxEntropy)
        }
    }
    return ExfiltrationCheckResult(null, maxEntropy)
}

fun checkPathAnalysis(path: String, defaults: PolicyDefaults?): PathAnalysisResult {
    val inspection = defaults?.urlInspection ?: return PathAnalysisResult(null)
    return checkTraversal(path, inspection)
        ?: checkDoubleEncoding(path, inspection)
        ?: checkInvalidPercentEncoding(path, inspection)
        ?: checkUrlLength(path, inspection)
        ?: checkPathLength(path, inspection)
        ?: checkPathEntropy(path, inspection)
        ?: PathAnalysisResult(null, pathEntropyScore = path.maxSegmentEntropy().takeIf { it > 0.0 })
}

private fun checkTraversal(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    if (inspection.blockPathTraversal != true || !PathAnalyzer.detectPathTraversal(path)) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.PATH_TRAVERSAL_BLOCKED),
        pathTraversalDetected = true
    )
}

private fun checkDoubleEncoding(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    if (inspection.blockDoubleEncoding != true || !PathAnalyzer.detectDoubleEncoding(path)) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.DOUBLE_ENCODING_BLOCKED)
    )
}

private val INVALID_PERCENT_ENCODING = Regex("%(?![0-9A-Fa-f]{2})")

private fun checkInvalidPercentEncoding(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    if (inspection.blockInvalidPercentEncoding == false) return null
    if (!INVALID_PERCENT_ENCODING.containsMatchIn(path)) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.INVALID_PERCENT_ENCODING_BLOCKED)
    )
}

private fun checkUrlLength(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    val maxUrlLength = inspection.maxUrlLength ?: return null
    if (path.length <= maxUrlLength) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.PATH_LENGTH_EXCEEDED)
    )
}

private fun checkPathLength(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    val maxPathLength = inspection.maxPathLength ?: return null
    val pathOnly = path.substringBefore('?')
    if (pathOnly.length <= maxPathLength) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.PATH_LENGTH_EXCEEDED)
    )
}

private fun checkPathEntropy(path: String, inspection: PolicyUrlInspection): PathAnalysisResult? {
    val threshold = inspection.pathEntropyThreshold ?: return null
    val maxSegEntropy = path.maxSegmentEntropy()
    if (maxSegEntropy <= threshold) return null
    return PathAnalysisResult(
        decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.URL_EXFILTRATION_BLOCKED),
        pathEntropyScore = maxSegEntropy
    )
}
