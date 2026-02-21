package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseKey
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.inspection.ContentInspectionPhase
import com.mustafadakhel.oag.pipeline.DnsExfiltrationKey

class DataBudgetPhase(
    private val policyService: PolicyService,
    private val dataBudgetTracker: DataBudgetTracker
) : GatePhase {
    companion object : PhaseKey<Long>
    override val name = "data_budget"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkDataBudgetPhase(context, policyService, dataBudgetTracker)
}

fun checkDataBudgetPhase(
    context: RequestPipelineContext,
    policyService: PolicyService,
    dataBudgetTracker: DataBudgetTracker
): PhaseOutcome<Unit> {
    val dataBudgetLimit = policyService.current.defaults?.maxBytesPerHostPerSession
    val sessionId = context.config.params.sessionId
    if (dataBudgetLimit == null || sessionId == null) return PhaseOutcome.Continue(Unit)

    val bodyBytes = context.bufferedBody?.size?.toLong()
        ?: (context.request.headers[HttpConstants.CONTENT_LENGTH]?.toLongOrNull() ?: 0L)
    if (bodyBytes > 0 && !dataBudgetTracker.recordAndCheck(sessionId, context.target.host, bodyBytes, dataBudgetLimit)) {
        val usedBytes = dataBudgetTracker.currentUsage(sessionId, context.target.host)
        context.outputs.put(DataBudgetPhase, usedBytes)
        val budgetDecision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.DATA_BUDGET_EXCEEDED)
        context.debugLog { "data budget exceeded host=${context.target.host}" }
        return PhaseOutcome.Deny(
            decision = budgetDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(
                contentInspection = AuditContentInspection(
                    bodyInspected = ContentInspectionPhase in context.outputs,
                    dnsEntropyScore = context.outputs.getOrNull(DnsExfiltrationKey)?.maxEntropy,
                    dataBudgetUsedBytes = usedBytes
                ),
                tags = context.matchedTags,
                agentProfileId = context.agentProfileId
            )
        )
    }
    context.outputs.put(DataBudgetPhase, dataBudgetTracker.currentUsage(sessionId, context.target.host))
    return PhaseOutcome.Continue(Unit)
}
