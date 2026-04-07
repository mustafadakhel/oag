package com.mustafadakhel.oag

object FindingSeverityLabels {
    val valid: Set<String> = FindingSeverity.entries.map { it.label() }.toSet()
}

object FindingTypeLabels {
    val valid: Set<String> = FindingType.entries.map { it.label() }.toSet()
}

object WebhookEventLabels {
    val valid: Set<String> = setOf(
        "circuit_open", "reload_failed", "injection_detected",
        "credential_detected", "integrity_drift", "admin_denied",
        "hallucination_detected",
        "schema_validation_failed"
    )
}
