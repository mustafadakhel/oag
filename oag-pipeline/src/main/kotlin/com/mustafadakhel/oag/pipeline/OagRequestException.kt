package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyErrorResponse
import com.mustafadakhel.oag.policy.core.ReasonCode

sealed class OagRequestException : Exception() {
    abstract val decision: PolicyDecision
    abstract val status: HttpStatus
    abstract val extras: AuditExtras

    override fun fillInStackTrace(): Throwable = this

    class PolicyDenied(
        override val decision: PolicyDecision,
        override val status: HttpStatus,
        override val extras: AuditExtras = AuditExtras(),
        val errorResponse: PolicyErrorResponse? = null,
        val enforcementActions: List<EnforcementAction> = emptyList()
    ) : OagRequestException()

    class UpstreamFailure(
        ruleId: String?,
        val retryCount: Int = 0,
        override val extras: AuditExtras = AuditExtras(),
        cause: Throwable? = null
    ) : OagRequestException() {
        override val decision = PolicyDecision(
            action = PolicyAction.DENY, ruleId = ruleId,
            reasonCode = ReasonCode.UPSTREAM_CONNECTION_FAILED
        )
        override val status: HttpStatus get() = HttpStatus.BAD_GATEWAY

        init { cause?.let { initCause(it) } }
    }

    class InvalidRequest(
        ruleId: String?,
        override val extras: AuditExtras = AuditExtras()
    ) : OagRequestException() {
        override val decision = PolicyDecision(
            action = PolicyAction.DENY, ruleId = ruleId,
            reasonCode = ReasonCode.INVALID_REQUEST
        )
        override val status: HttpStatus get() = HttpStatus.BAD_REQUEST
    }
}

inline fun <T> wrapUpstreamFailure(ruleId: String?, extras: AuditExtras = AuditExtras(), block: () -> T): T =
    try {
        block()
    } catch (e: OagRequestException) {
        throw e
    } catch (e: Exception) {
        throw OagRequestException.UpstreamFailure(ruleId, extras = extras, cause = e)
    }
