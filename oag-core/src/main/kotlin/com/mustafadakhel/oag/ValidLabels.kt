package com.mustafadakhel.oag

object FindingSeverityLabels {
    val valid: Set<String> = setOf("low", "medium", "high", "critical")
}

object FindingTypeLabels {
    val valid: Set<String> = setOf(
        "prompt_injection", "credential", "pii", "dns_exfiltration",
        "url_exfiltration", "path_traversal", "structured_payload",
        "body_match", "redirect_target", "custom"
    )
}

object WebhookEventLabels {
    val valid: Set<String> = setOf(
        "circuit_open", "reload_failed", "injection_detected",
        "credential_detected", "integrity_drift", "admin_denied"
    )
}
