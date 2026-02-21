package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyErrorResponse

import com.mustafadakhel.oag.enforcement.EnforcementAction

import java.net.InetAddress

enum class HttpStatus(val code: Int) {
    SWITCHING_PROTOCOLS(101),
    OK(200),
    BAD_REQUEST(400),
    UNAUTHORIZED(401),
    FORBIDDEN(403),
    NOT_FOUND(404),
    METHOD_NOT_ALLOWED(405),
    TOO_MANY_REQUESTS(429),
    INTERNAL_SERVER_ERROR(500),
    NOT_IMPLEMENTED(501),
    BAD_GATEWAY(502),
    SERVICE_UNAVAILABLE(503)
}

sealed class PhaseOutcome<out T> {
    data class Continue<T>(val value: T) : PhaseOutcome<T>()
    data class Deny(
        val decision: PolicyDecision,
        val statusCode: HttpStatus,
        val auditExtras: AuditExtras = AuditExtras(),
        val errorResponse: PolicyErrorResponse? = null,
        val enforcementActions: List<EnforcementAction> = emptyList()
    ) : PhaseOutcome<Nothing>() {
        val enforcementAction: EnforcementAction.Deny
            get() = EnforcementAction.Deny(
                reason = decision.effectiveReasonCode(),
                statusCode = statusCode.code
            )
    }
}

data class AuditExtras(
    val contentInspection: AuditContentInspection? = null,
    val tags: List<String>? = null,
    val agentProfileId: String? = null,
    val secretIds: List<String> = emptyList(),
    val injectionAttempted: Boolean = false,
    val secretVersions: Map<String, String> = emptyMap(),
    val resolvedIps: List<InetAddress>? = null
)
