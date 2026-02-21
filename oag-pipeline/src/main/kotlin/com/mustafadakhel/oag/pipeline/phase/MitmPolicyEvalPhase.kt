package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.ConnectFallbackData
import com.mustafadakhel.oag.pipeline.ConnectFallbackKey
import com.mustafadakhel.oag.pipeline.DnsResolutionKey
import com.mustafadakhel.oag.pipeline.DnsResolutionResult
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PolicyEvalKey
import com.mustafadakhel.oag.pipeline.PolicyPhaseResult
import com.mustafadakhel.oag.pipeline.RequestPipelineContext

class MitmPolicyEvalPhase(
    private val policyService: PolicyService
) : GatePhase {
    override val stage = PipelineStage.POLICY
    override val name = "mitm_policy_eval"
    override val producesKeys = setOf(PolicyEvalKey)

    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        val agentProfile = policyService.resolveAgentProfile(context.resolvedAgentId)
        val match = policyService.evaluateWithRule(context.toPolicyRequest(), agentProfile)

        val fallback = context.outputs.getOrNull(ConnectFallbackKey)
        val connectFallback = match.rule == null && fallback?.matchedRule != null
        val matchedRule = match.rule
        val fallbackTag = if (connectFallback) listOf("connect_rule_fallback") else emptyList()
        val tags = (matchedRule?.tags.orEmpty() + fallbackTag).ifEmpty { null }

        if (connectFallback) {
            context.debugLog { "MITM inner request fell back to CONNECT rule=${fallback?.matchedRule?.id} for path=${context.target.path}" }
        }

        context.outputs.put(PolicyEvalKey, PolicyPhaseResult(
            decision = match.decision, rule = matchedRule,
            agentProfile = agentProfile, tags = tags
        ))
        if (fallback != null) {
            context.outputs.put(DnsResolutionKey, DnsResolutionResult(
                ips = fallback.resolvedIps, failed = false
            ))
        }

        context.debugLog { "policy action=${match.decision.action.label()} reason=${match.decision.effectiveReasonCode()} rule=${match.decision.ruleId ?: "-"}" }

        if (match.decision.action == PolicyAction.DENY) {
            return PhaseOutcome.Deny(
                decision = match.decision,
                statusCode = HttpStatus.FORBIDDEN,
                auditExtras = AuditExtras(
                    tags = tags,
                    agentProfileId = agentProfile?.id
                ),
                errorResponse = matchedRule?.errorResponse
            )
        }
        return PhaseOutcome.Continue(Unit)
    }
}
