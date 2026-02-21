package com.mustafadakhel.oag.pipeline.network

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.shannonEntropy
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.DnsExfiltrationKey
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.inspection.ExfiltrationCheckResult

class DnsExfiltrationPhase(
    private val policyService: PolicyService
) : GatePhase {
    override val stage = PipelineStage.TARGET
    override val name = "dns_exfiltration"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkDnsExfiltrationPhase(context, policyService)
}

private const val DEFAULT_DNS_ENTROPY_THRESHOLD = 4.0
const val DEFAULT_DNS_MIN_LABEL_LENGTH = 20

fun checkDnsExfiltration(host: String, defaults: PolicyDefaults?): ExfiltrationCheckResult {
    if (defaults?.blockDnsExfiltration != true) return ExfiltrationCheckResult(null)
    val threshold = defaults.dnsEntropyThreshold ?: DEFAULT_DNS_ENTROPY_THRESHOLD
    val minLabelLength = defaults.dnsMinLabelLength ?: DEFAULT_DNS_MIN_LABEL_LENGTH
    val labels = host.split('.')
    val entropies = labels.filter { it.length >= minLabelLength }.map { it.shannonEntropy() }
    val maxEntropy = entropies.maxOrNull()
    if (entropies.any { it > threshold }) {
        return ExfiltrationCheckResult(
            PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.DNS_EXFILTRATION_BLOCKED),
            maxEntropy
        )
    }
    return ExfiltrationCheckResult(null, maxEntropy)
}

fun checkDnsExfiltrationPhase(context: RequestPipelineContext, policyService: PolicyService): PhaseOutcome<Unit> {
    val result = checkDnsExfiltration(context.target.host, policyService.current.defaults)
    context.outputs.put(DnsExfiltrationKey, result)
    if (result.decision != null) {
        context.debugLog { "dns exfiltration blocked host=${context.target.host}" }
        return PhaseOutcome.Deny(
            decision = result.decision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = AuditExtras(
                contentInspection = AuditContentInspection(dnsEntropyScore = result.maxEntropy)
            )
        )
    }
    return PhaseOutcome.Continue(Unit)
}
