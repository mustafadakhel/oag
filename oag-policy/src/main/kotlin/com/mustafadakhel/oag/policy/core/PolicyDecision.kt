package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.label

data class PolicyDecision(
    val action: PolicyAction,
    val ruleId: String?,
    val reasonCode: ReasonCode,
    val customReasonCode: String? = null
) {
    fun effectiveReasonCode(): String = customReasonCode ?: reasonCode.label()
}

enum class ReasonCategory {
    POLICY,
    NETWORK,
    SECURITY,
    VALIDATION,
    RESOURCE
}

enum class ReasonCode(val category: ReasonCategory) {
    DENIED_BY_RULE(ReasonCategory.POLICY),
    ALLOWED_BY_RULE(ReasonCategory.POLICY),
    NO_MATCH_DEFAULT_ALLOW(ReasonCategory.POLICY),
    NO_MATCH_DEFAULT_DENY(ReasonCategory.POLICY),
    AGENT_PROFILE_DENIED(ReasonCategory.POLICY),

    RAW_IP_LITERAL_BLOCKED(ReasonCategory.NETWORK),
    DNS_RESOLVED_PRIVATE_RANGE_BLOCKED(ReasonCategory.NETWORK),
    DNS_RESOLUTION_FAILED(ReasonCategory.NETWORK),
    REDIRECT_TARGET_DENIED(ReasonCategory.NETWORK),
    UPSTREAM_CONNECTION_FAILED(ReasonCategory.NETWORK),
    CIRCUIT_OPEN(ReasonCategory.NETWORK),

    INJECTION_DETECTED(ReasonCategory.SECURITY),
    RESPONSE_INJECTION_DETECTED(ReasonCategory.SECURITY),
    URL_EXFILTRATION_BLOCKED(ReasonCategory.SECURITY),
    DNS_EXFILTRATION_BLOCKED(ReasonCategory.SECURITY),
    OUTBOUND_CREDENTIAL_DETECTED(ReasonCategory.SECURITY),
    SENSITIVE_DATA_DETECTED(ReasonCategory.SECURITY),
    PATH_TRAVERSAL_BLOCKED(ReasonCategory.SECURITY),
    DOUBLE_ENCODING_BLOCKED(ReasonCategory.SECURITY),
    INVALID_PERCENT_ENCODING_BLOCKED(ReasonCategory.SECURITY),
    SIGNATURE_INVALID(ReasonCategory.SECURITY),
    PLUGIN_DETECTED(ReasonCategory.SECURITY),
    RESPONSE_PLUGIN_DETECTED(ReasonCategory.SECURITY),

    BODY_TOO_LARGE(ReasonCategory.VALIDATION),
    BODY_MATCH_FAILED(ReasonCategory.VALIDATION),
    INVALID_REQUEST(ReasonCategory.VALIDATION),
    PATH_LENGTH_EXCEEDED(ReasonCategory.VALIDATION),

    RATE_LIMITED(ReasonCategory.RESOURCE),
    VELOCITY_SPIKE_DETECTED(ReasonCategory.RESOURCE),
    DATA_BUDGET_EXCEEDED(ReasonCategory.RESOURCE),
    TOKEN_BUDGET_EXCEEDED(ReasonCategory.RESOURCE),
    SECRET_MATERIALIZATION_FAILED(ReasonCategory.RESOURCE);

}
