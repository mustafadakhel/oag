package com.mustafadakhel.oag.pipeline

object WebhookPayloadKeys {
    // Event type values
    const val EVENT_CIRCUIT_OPEN = "circuit_open"
    const val EVENT_RELOAD_FAILED = "reload_failed"
    const val EVENT_INJECTION_DETECTED = "injection_detected"
    const val EVENT_CREDENTIAL_DETECTED = "credential_detected"
    const val EVENT_INTEGRITY_DRIFT = "integrity_drift"
    const val EVENT_ADMIN_DENIED = "admin_denied"

    // Data map keys
    const val DATA_HOST = "host"
    const val DATA_PREVIOUS_STATE = "previous_state"
    const val DATA_NEW_STATE = "new_state"
    const val DATA_TRIGGER = "trigger"
    const val DATA_ERROR = "error"
    const val DATA_PATH = "path"
    const val DATA_METHOD = "method"
    const val DATA_PATTERNS = "patterns"
    const val DATA_CREDENTIALS = "credentials"
    const val DATA_SOURCE_IP = "source_ip"
    const val DATA_ENDPOINT = "endpoint"
    const val DATA_STATUS = "status"
    const val DATA_POLICY_HASH_MATCH = "policy_hash_match"
    const val DATA_CONFIG_FINGERPRINT_MATCH = "config_fingerprint_match"
}
