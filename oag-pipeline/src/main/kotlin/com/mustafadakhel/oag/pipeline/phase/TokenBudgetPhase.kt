package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker

import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext

class TokenBudgetPhase(
    private val policyService: PolicyService,
    private val tokenBudgetTracker: TokenBudgetTracker
) : GatePhase {
    override val name = "token_budget"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkTokenBudgetPhase(context, policyService, tokenBudgetTracker)
}

fun checkTokenBudgetPhase(
    context: RequestPipelineContext,
    policyService: PolicyService,
    tokenBudgetTracker: TokenBudgetTracker
): PhaseOutcome<Unit> {
    val tokenLimit = policyService.current.defaults?.maxTokensPerSession
    val sessionId = context.config.params.sessionId
    if (tokenLimit == null || sessionId == null) return PhaseOutcome.Continue(Unit)

    val currentUsage = tokenBudgetTracker.currentUsage(sessionId)
    if (currentUsage >= tokenLimit) {
        context.debugLog { "token budget exceeded session=$sessionId usage=$currentUsage limit=$tokenLimit" }
        return PhaseOutcome.Deny(
            decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.TOKEN_BUDGET_EXCEEDED),
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId)
        )
    }
    return PhaseOutcome.Continue(Unit)
}
