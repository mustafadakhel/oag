package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.audit.AuditHeaderRewrite
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.pipeline.inspection.ExfiltrationCheckResult
import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.StructuredPayload
import com.mustafadakhel.oag.secrets.SecretInjectionResult

import java.net.InetAddress

object HeaderState : PhaseKey<Map<String, String>>

data class BodyBufferResult(
    val body: ByteArray,
    val bodyText: String,
    val structuredPayload: StructuredPayload? = null
)

object BodyBufferKey : PhaseKey<BodyBufferResult>

data class DnsResolutionResult(
    val ips: List<InetAddress>,
    val failed: Boolean
)

object DnsResolutionKey : PhaseKey<DnsResolutionResult>

data class PolicyPhaseResult(
    val decision: PolicyDecision,
    val rule: PolicyRule?,
    val agentProfile: PolicyAgentProfile?,
    val tags: List<String>?
)

object PolicyEvalKey : PhaseKey<PolicyPhaseResult>

object SecretInjectionKey : PhaseKey<SecretInjectionResult>

object SignatureKey : PhaseKey<IdentityResult>

object RequestIdKey : PhaseKey<RequestId>

object HeaderRewritesKey : PhaseKey<List<AuditHeaderRewrite>>

object DnsExfiltrationKey : PhaseKey<ExfiltrationCheckResult>

data class PluginDetectionResult(
    val findings: List<Finding>,
    val detectorIds: List<String>,
    val suppressedCount: Int = 0
)

object PluginDetectionKey : PhaseKey<PluginDetectionResult>

object FindingRedactionKey : PhaseKey<List<Finding>>

object FindingAuditKey : PhaseKey<List<Finding>>

data class ConnectFallbackData(
    val matchedRule: PolicyRule?,
    val resolvedIps: List<InetAddress>
)

object ConnectFallbackKey : PhaseKey<ConnectFallbackData>
