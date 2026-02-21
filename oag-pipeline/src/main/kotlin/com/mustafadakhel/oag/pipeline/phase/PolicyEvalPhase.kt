package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PolicyEvalKey
import com.mustafadakhel.oag.pipeline.PolicyPhaseResult
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.Phase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.network.IpBlockPhase
import com.mustafadakhel.oag.pipeline.network.ResolvedIpBlockPhase
import com.mustafadakhel.oag.pipeline.network.ipBlockDecision
import com.mustafadakhel.oag.telemetry.RequestProfiler

private const val AGENT_PROFILE_KEY_PREFIX = "__agent_profile__"

class PolicyEvalPhase(
    private val policyService: PolicyService
) : GatePhase {
    override val stage = PipelineStage.POLICY
    override val name = "policy_evaluation"
    override val producesKeys = setOf(PolicyEvalKey)
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        context.profiler.measure(RequestProfiler.PHASE_POLICY_EVALUATION) {
            evaluatePolicyPhase(
                context = context,
                policyService = policyService,
                ipBlockDecision = context.outputs.getOrNull(IpBlockPhase),
                resolvedIpDecision = context.outputs.getOrNull(ResolvedIpBlockPhase)
            )
        }
}

class RateLimitPhase(
    private val rateLimiterRegistry: RateLimiterRegistry
) : GatePhase {
    override val stage = PipelineStage.POLICY
    override val name = "rate_limit"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkRateLimitPhase(context, rateLimiterRegistry)
}

class AgentProfilePhase(
    private val rateLimiterRegistry: RateLimiterRegistry
) : GatePhase {
    override val stage = PipelineStage.POLICY
    override val name = "agent_profile"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkAgentProfilePhase(context, rateLimiterRegistry)
}

fun evaluatePolicyPhase(
    context: RequestPipelineContext,
    policyService: PolicyService,
    ipBlockDecision: PolicyDecision?,
    resolvedIpDecision: PolicyDecision?
): PhaseOutcome<Unit> {
    val agentProfile = policyService.resolveAgentProfile(context.resolvedAgentId)

    val policyRequest = context.toPolicyRequest()
    val match = policyService.evaluateWithRule(policyRequest, agentProfile)
    val tags = match.rule?.tags

    val policyDecision = ipBlockDecision ?: resolvedIpDecision ?: match.decision
    context.outputs.put(PolicyEvalKey, PolicyPhaseResult(
        decision = policyDecision, rule = match.rule,
        agentProfile = agentProfile, tags = tags
    ))
    context.debugLog { "policy action=${policyDecision.action.label()} reason=${policyDecision.effectiveReasonCode()} rule=${policyDecision.ruleId ?: "-"}" }

    if (policyDecision.action == PolicyAction.DENY) {
        return PhaseOutcome.Deny(
            decision = policyDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(
                tags = tags,
                agentProfileId = agentProfile?.id
            ),
            errorResponse = match.rule?.errorResponse
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkRateLimitPhase(context: RequestPipelineContext, rateLimiterRegistry: RateLimiterRegistry): PhaseOutcome<Unit> {
    val rule = context.matchedRule ?: return PhaseOutcome.Continue(Unit)
    val decision = context.policyDecision ?: return PhaseOutcome.Continue(Unit)
    val ruleId = decision.ruleId
    if (rule.rateLimit != null && ruleId != null) {
        if (!rateLimiterRegistry.tryAcquire(ruleId)) {
            val rateLimitDecision = PolicyDecision(
                action = PolicyAction.DENY,
                ruleId = decision.ruleId,
                reasonCode = ReasonCode.RATE_LIMITED
            )
            context.debugLog { "rate limited rule=${decision.ruleId}" }
            return PhaseOutcome.Deny(
                decision = rateLimitDecision,
                statusCode = HttpStatus.TOO_MANY_REQUESTS,
                auditExtras = AuditExtras(
                    tags = context.matchedTags,
                    agentProfileId = context.agentProfileId
                )
            )
        }
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkAgentProfilePhase(context: RequestPipelineContext, rateLimiterRegistry: RateLimiterRegistry): PhaseOutcome<Unit> {
    val profile = context.agentProfile ?: return PhaseOutcome.Continue(Unit)
    checkAgentRateLimit(context, profile, rateLimiterRegistry)?.let { return it }
    checkAgentBodySize(context, profile)?.let { return it }
    return PhaseOutcome.Continue(Unit)
}

private fun checkAgentRateLimit(
    context: RequestPipelineContext,
    profile: PolicyAgentProfile,
    rateLimiterRegistry: RateLimiterRegistry
): PhaseOutcome.Deny? {
    val maxRequestsPerMinute = profile.maxRequestsPerMinute ?: return null
    val profileRateKey = "$AGENT_PROFILE_KEY_PREFIX${profile.id}"
    if (rateLimiterRegistry.getOrCreateAndAcquire(profileRateKey, maxRequestsPerMinute)) return null
    context.debugLog { "agent profile rate limited profile=${profile.id}" }
    return PhaseOutcome.Deny(
        decision = PolicyDecision(
            action = PolicyAction.DENY,
            ruleId = null,
            reasonCode = ReasonCode.AGENT_PROFILE_DENIED
        ),
        statusCode = HttpStatus.TOO_MANY_REQUESTS,
        auditExtras = AuditExtras(
            tags = context.matchedTags,
            agentProfileId = context.agentProfileId
        )
    )
}

private fun checkAgentBodySize(
    context: RequestPipelineContext,
    profile: PolicyAgentProfile
): PhaseOutcome.Deny? {
    val maxBodyBytes = profile.maxBodyBytes ?: return null
    val contentLength = context.request.headers[HttpConstants.CONTENT_LENGTH]?.toLongOrNull() ?: return null
    if (contentLength <= maxBodyBytes) return null
    context.debugLog { "agent profile body too large profile=${profile.id} content_length=$contentLength max=$maxBodyBytes" }
    return PhaseOutcome.Deny(
        decision = PolicyDecision(
            action = PolicyAction.DENY,
            ruleId = null,
            reasonCode = ReasonCode.AGENT_PROFILE_DENIED,
            customReasonCode = "agent_profile_body_too_large"
        ),
        statusCode = HttpStatus.FORBIDDEN,
        auditExtras = AuditExtras(
            tags = context.matchedTags,
            agentProfileId = context.agentProfileId
        )
    )
}

class ConnectPolicyEvalPhase(
    private val policyService: PolicyService
) : GatePhase {
    override val stage = PipelineStage.POLICY
    override val name = "connect_policy_eval"
    override val producesKeys = setOf(PolicyEvalKey)
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        evaluateConnectPolicy(context, policyService)
}

fun evaluateConnectPolicy(
    context: RequestPipelineContext,
    policyService: PolicyService
): PhaseOutcome<Unit> {
    val ipBlock = context.outputs.getOrNull(IpBlockPhase)
    val resolvedIpBlock = context.outputs.getOrNull(ResolvedIpBlockPhase)

    val policyRequest = PolicyRequest(
        scheme = context.target.scheme, host = context.target.host, port = context.target.port,
        method = context.request.method, path = ""
    )
    val match = policyService.evaluateWithRule(policyRequest)
    val tags = match.rule?.tags

    val connectDecision = ipBlock ?: resolvedIpBlock ?: match.decision
    context.outputs.put(PolicyEvalKey, PolicyPhaseResult(
        decision = connectDecision, rule = match.rule,
        agentProfile = null, tags = tags
    ))
    context.debugLog {
        "policy action=${connectDecision.action.label()} reason=${connectDecision.effectiveReasonCode()} rule=${connectDecision.ruleId ?: "-"}"
    }

    if (connectDecision.action == PolicyAction.DENY) {
        return PhaseOutcome.Deny(
            connectDecision, HttpStatus.FORBIDDEN,
            AuditExtras(tags = context.matchedTags), match.rule?.errorResponse
        )
    }
    return PhaseOutcome.Continue(Unit)
}
