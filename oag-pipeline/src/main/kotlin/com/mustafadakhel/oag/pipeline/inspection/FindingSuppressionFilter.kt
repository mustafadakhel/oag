package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.policy.core.PolicyFindingSuppression

data class SuppressionResult(
    val kept: List<Finding>,
    val suppressed: List<Finding>
)

fun suppressFindings(
    findings: List<Finding>,
    suppressions: List<PolicyFindingSuppression>?,
    host: String?
): SuppressionResult {
    if (suppressions.isNullOrEmpty() || findings.isEmpty()) {
        return SuppressionResult(kept = findings, suppressed = emptyList())
    }
    val kept = mutableListOf<Finding>()
    val suppressed = mutableListOf<Finding>()
    for (finding in findings) {
        if (suppressions.any { it.matches(finding, host) }) {
            suppressed.add(finding)
        } else {
            kept.add(finding)
        }
    }
    return SuppressionResult(kept = kept, suppressed = suppressed)
}

private fun PolicyFindingSuppression.matches(finding: Finding, host: String?): Boolean {
    val did = detectorId
    if (did != null && finding.evidence["source"] != did) return false
    val ft = findingType
    if (ft != null && !finding.type.name.equals(ft, ignoreCase = true)) return false
    val pat = pattern
    if (pat != null && !finding.evidence.values.any { it.contains(pat) }) return false
    val h = hosts
    if (h != null && host != null && !h.any { hostPattern ->
            if (hostPattern.startsWith("*.")) host.endsWith(hostPattern.removePrefix("*"))
            else host.equals(hostPattern, ignoreCase = true)
        }) return false
    return true
}
