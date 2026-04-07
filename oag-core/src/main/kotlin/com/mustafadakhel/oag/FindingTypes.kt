package com.mustafadakhel.oag

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
    CUSTOM,
    HALLUCINATION,
    CODE_VULNERABILITY
}

enum class FindingSeverity {
    LOW, MEDIUM, HIGH, CRITICAL
}
