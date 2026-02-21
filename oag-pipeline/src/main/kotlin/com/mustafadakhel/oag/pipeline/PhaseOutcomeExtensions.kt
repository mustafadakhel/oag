package com.mustafadakhel.oag.pipeline
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode

fun RequestPipelineContext.denyPhase(
    reasonCode: ReasonCode,
    statusCode: HttpStatus = HttpStatus.FORBIDDEN,
    auditExtras: AuditExtras = AuditExtras(tags = matchedTags, agentProfileId = agentProfileId)
): PhaseOutcome.Deny = PhaseOutcome.Deny(
    decision = PolicyDecision(
        action = PolicyAction.DENY,
        ruleId = policyDecision?.ruleId,
        reasonCode = reasonCode
    ),
    statusCode = statusCode,
    auditExtras = auditExtras
)
