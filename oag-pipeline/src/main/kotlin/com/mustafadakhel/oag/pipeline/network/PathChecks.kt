package com.mustafadakhel.oag.pipeline.network

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseKey
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.DnsExfiltrationKey
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.inspection.ContentInspectionPhase
import com.mustafadakhel.oag.pipeline.inspection.ExfiltrationCheckResult
import com.mustafadakhel.oag.pipeline.inspection.PathAnalysisResult
import com.mustafadakhel.oag.pipeline.phase.DataBudgetPhase

class PathValidationPhase : GatePhase {
    override val stage = PipelineStage.TARGET
    override val name = "path_validation"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        validatePathPhase(context)
}

class UrlExfiltrationPhase(
    private val policyService: PolicyService
) : GatePhase {
    companion object : PhaseKey<ExfiltrationCheckResult>
    override val stage = PipelineStage.INSPECT
    override val name = "url_exfiltration"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkUrlExfiltrationPhase(context, policyService)
}

class PathAnalysisPhase(
    private val policyService: PolicyService
) : GatePhase {
    companion object : PhaseKey<PathAnalysisResult>
    override val stage = PipelineStage.INSPECT
    override val name = "path_analysis"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkPathAnalysisPhase(context, policyService)
}

fun validatePathPhase(context: RequestPipelineContext): PhaseOutcome<Unit> {
    if (!context.target.path.startsWith("/") && context.target.path != "*") {
        return PhaseOutcome.Deny(
            decision = PolicyDecision(
                action = PolicyAction.DENY,
                ruleId = null,
                reasonCode = ReasonCode.INVALID_REQUEST
            ),
            statusCode = HttpStatus.BAD_REQUEST
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkUrlExfiltrationPhase(context: RequestPipelineContext, policyService: PolicyService): PhaseOutcome<Unit> {
    val result = checkUrlExfiltration(context.target.path, policyService.current.defaults)
    context.outputs.put(UrlExfiltrationPhase, result)
    val urlDecision = result.decision
    if (urlDecision != null) {
        context.debugLog { "url exfiltration blocked in query string" }
        return PhaseOutcome.Deny(
            decision = urlDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(
                contentInspection = AuditContentInspection(
                    bodyInspected = ContentInspectionPhase in context.outputs,
                    urlEntropyScore = result.maxEntropy,
                    dnsEntropyScore = context.outputs.getOrNull(DnsExfiltrationKey)?.maxEntropy,
                    dataBudgetUsedBytes = context.outputs.getOrNull(DataBudgetPhase)
                ),
                tags = context.matchedTags,
                agentProfileId = context.agentProfileId
            )
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkPathAnalysisPhase(context: RequestPipelineContext, policyService: PolicyService): PhaseOutcome<Unit> {
    val result = checkPathAnalysis(context.target.path, policyService.current.defaults)
    context.outputs.put(PathAnalysisPhase, result)
    val pathDecision = result.decision
    if (pathDecision != null) {
        context.debugLog { "path analysis blocked: ${pathDecision.reasonCode.label()}" }
        return PhaseOutcome.Deny(
            decision = pathDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(
                contentInspection = AuditContentInspection(
                    bodyInspected = ContentInspectionPhase in context.outputs,
                    dnsEntropyScore = context.outputs.getOrNull(DnsExfiltrationKey)?.maxEntropy,
                    pathEntropyScore = result.pathEntropyScore,
                    pathTraversalDetected = result.pathTraversalDetected.takeIf { it }
                ),
                tags = context.matchedTags,
                agentProfileId = context.agentProfileId
            )
        )
    }
    return PhaseOutcome.Continue(Unit)
}
