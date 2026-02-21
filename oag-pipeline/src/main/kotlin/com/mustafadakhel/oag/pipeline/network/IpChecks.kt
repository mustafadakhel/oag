package com.mustafadakhel.oag.pipeline.network

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.isSpecialPurposeAddress
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.http.isIpLiteralHost
import com.mustafadakhel.oag.pipeline.DnsResolutionKey
import com.mustafadakhel.oag.pipeline.DnsResolutionResult
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseKey
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.Phase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.telemetry.RequestProfiler

import java.net.InetAddress

class IpBlockPhase : GatePhase {
    companion object : PhaseKey<PolicyDecision>
    override val stage = PipelineStage.TARGET
    override val name = "ip_block"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        val decision = ipBlockDecision(context.target.host, context.config.network.blockIpLiterals)
        if (decision != null) {
            context.outputs.put(IpBlockPhase, decision)
            return PhaseOutcome.Deny(decision, HttpStatus.FORBIDDEN)
        }
        return PhaseOutcome.Continue(Unit)
    }
}

class DnsResolutionPhase(
    private val policyService: PolicyService,
    private val hostResolver: HostResolver
) : Phase {
    override val stage = PipelineStage.TARGET
    override val name = "dns_resolution"
    override suspend fun execute(context: RequestPipelineContext) {
        context.profiler.measure(RequestProfiler.PHASE_DNS_RESOLUTION) {
            context.outputs.put(DnsResolutionKey, resolveIps(context, policyService, hostResolver))
        }
    }
}

class ResolvedIpBlockPhase : GatePhase {
    companion object : PhaseKey<PolicyDecision>
    override val stage = PipelineStage.TARGET
    override val name = "resolved_ip_block"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        val decision = resolvedIpBlockDecision(
            context.target.host, context.resolvedIps,
            context.config.network.blockPrivateResolvedIps, context.dnsResolutionFailed
        )
        if (decision != null) {
            context.outputs.put(ResolvedIpBlockPhase, decision)
            return PhaseOutcome.Deny(decision, HttpStatus.FORBIDDEN)
        }
        return PhaseOutcome.Continue(Unit)
    }
}

class DnsResolutionCheckPhase(
    private val policyService: PolicyService
) : GatePhase {
    override val stage = PipelineStage.TARGET
    override val name = "dns_resolution_check"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkDnsResolutionPhase(context, policyService)
}

fun ipBlockDecision(host: String, blockIpLiterals: Boolean): PolicyDecision? {
    if (!blockIpLiterals) return null
    if (!isIpLiteralHost(host)) return null
    return PolicyDecision(
        action = PolicyAction.DENY,
        ruleId = null,
        reasonCode = ReasonCode.RAW_IP_LITERAL_BLOCKED
    )
}

fun resolveIps(
    context: RequestPipelineContext,
    policyService: PolicyService,
    hostResolver: HostResolver
): DnsResolutionResult {
    val enforceDnsResolution = policyService.current.defaults?.enforceDnsResolution == true
    val skipResolution = !(context.config.network.blockPrivateResolvedIps || enforceDnsResolution) ||
        isIpLiteralHost(context.target.host)
    if (skipResolution) {
        return DnsResolutionResult(ips = emptyList(), failed = false)
    }
    val result = runCatching { hostResolver.resolve(context.target.host) }
    return DnsResolutionResult(
        ips = result.getOrNull().orEmpty(),
        failed = result.isFailure
    )
}

fun checkDnsResolutionPhase(
    context: RequestPipelineContext,
    policyService: PolicyService
): PhaseOutcome<Unit> {
    val enforceDnsResolution = policyService.current.defaults?.enforceDnsResolution == true
    if (!enforceDnsResolution || isIpLiteralHost(context.target.host)) return PhaseOutcome.Continue(Unit)
    if (context.resolvedIps.isEmpty()) {
        return PhaseOutcome.Deny(
            decision = PolicyDecision(
                action = PolicyAction.DENY,
                ruleId = null,
                reasonCode = ReasonCode.DNS_RESOLUTION_FAILED
            ),
            statusCode = HttpStatus.FORBIDDEN
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun resolvedIpBlockDecision(
    host: String,
    resolvedIps: List<InetAddress>,
    blockPrivateResolvedIps: Boolean,
    dnsResolutionFailed: Boolean = false
): PolicyDecision? {
    if (!blockPrivateResolvedIps) return null
    if (dnsResolutionFailed) {
        return PolicyDecision(
            action = PolicyAction.DENY,
            ruleId = null,
            reasonCode = ReasonCode.DNS_RESOLUTION_FAILED
        )
    }
    if (resolvedIps.isEmpty()) return null
    if (!resolvedIps.any { it.isSpecialPurposeAddress() }) return null
    return PolicyDecision(
        action = PolicyAction.DENY,
        ruleId = null,
        reasonCode = ReasonCode.DNS_RESOLVED_PRIVATE_RANGE_BLOCKED
    )
}
