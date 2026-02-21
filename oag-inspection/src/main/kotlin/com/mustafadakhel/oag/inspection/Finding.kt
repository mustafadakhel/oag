package com.mustafadakhel.oag.inspection

data class Finding(
    val type: FindingType,
    val severity: FindingSeverity,
    val confidence: Double,
    val location: FindingLocation?,
    val evidence: Map<String, String>,
    val recommendedActions: List<RecommendedAction>
)

enum class FindingType {
    PROMPT_INJECTION,
    CREDENTIAL,
    PII,
    DNS_EXFILTRATION,
    URL_EXFILTRATION,
    PATH_TRAVERSAL,
    STRUCTURED_PAYLOAD,
    BODY_MATCH,
    REDIRECT_TARGET,
    CUSTOM
}

enum class FindingSeverity {
    LOW, MEDIUM, HIGH, CRITICAL
}
