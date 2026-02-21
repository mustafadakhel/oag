package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.audit.AuditDecision
import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditRedirectHop
import com.mustafadakhel.oag.audit.AuditRequest
import com.mustafadakhel.oag.audit.AuditResponse
import com.mustafadakhel.oag.audit.AuditResponseRewrite
import com.mustafadakhel.oag.audit.AuditSecrets
import com.mustafadakhel.oag.audit.AuditStructuredPayload
import com.mustafadakhel.oag.audit.AuditTokenUsage
import com.mustafadakhel.oag.audit.AuditTrace
import com.mustafadakhel.oag.audit.AuditWebSocketSession
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.secrets.SecretInjectionResult
import com.mustafadakhel.oag.telemetry.RequestProfiler
import com.mustafadakhel.oag.telemetry.RequestSpan

import java.io.InputStream
import java.net.InetAddress
import java.net.Socket

val EMPTY_INJECTION_RESULT = SecretInjectionResult(
    attemptedIds = emptyList(),
    injected = false,
    secretIds = emptyList(),
    errors = emptyList()
)

data class RequestContext(
    val config: HandlerConfig,
    val target: ParsedTarget,
    val request: HttpRequest,
    val trace: AuditTrace?,
    val connectionIdentity: IdentityResult? = null,
    val policyHash: String = "",
    val startNs: Long = System.nanoTime()
)

class RequestPipelineContext(
    val requestContext: RequestContext,
    val output: CountingOutputStream,
    val clientSocket: Socket? = null,
    val profiler: RequestProfiler = RequestProfiler(),
    val debugLog: (() -> String) -> Unit = {},
    val emitAudit: AuditEmitter = AuditEmitter {},
    val clientInput: InputStream? = null,
    val requestSpan: RequestSpan? = null
) {
    val config: HandlerConfig get() = requestContext.config
    val target: ParsedTarget get() = requestContext.target
    val request: HttpRequest get() = requestContext.request
    val trace: AuditTrace? get() = requestContext.trace
    val connectionIdentity: IdentityResult? get() = requestContext.connectionIdentity
    val policyHash: String get() = requestContext.policyHash
    val startNs: Long get() = requestContext.startNs

    val outputs: PhaseOutputs = PhaseOutputs()
    val dryRun get() = config.params.dryRun

    val headers: Map<String, String> get() = outputs.getOrNull(HeaderState) ?: emptyMap()
    val bufferedBody: ByteArray? get() = outputs.getOrNull(BodyBufferKey)?.body
    val bufferedBodyText: String? get() = outputs.getOrNull(BodyBufferKey)?.bodyText
    val resolvedIps: List<InetAddress> get() = outputs.getOrNull(DnsResolutionKey)?.ips ?: emptyList()
    val dnsResolutionFailed: Boolean get() = outputs.getOrNull(DnsResolutionKey)?.failed ?: false
    val policyDecision: PolicyDecision? get() = outputs.getOrNull(PolicyEvalKey)?.decision
    val matchedRule: PolicyRule? get() = outputs.getOrNull(PolicyEvalKey)?.rule
    val agentProfile: PolicyAgentProfile? get() = outputs.getOrNull(PolicyEvalKey)?.agentProfile
    val matchedTags: List<String>? get() = outputs.getOrNull(PolicyEvalKey)?.tags
    val injection: SecretInjectionResult get() = outputs.getOrNull(SecretInjectionKey)
        ?: EMPTY_INJECTION_RESULT
    val policyDenied get() = policyDecision?.action == PolicyAction.DENY
    val agentProfileId get() = agentProfile?.id
    val pluginDetectionResult: PluginDetectionResult?
        get() = outputs.getOrNull(PluginDetectionKey)

    /**
     * Agent identity resolved with highest-trust-first priority:
     * 1. Cryptographic signature verified via [SignatureKey] (HMAC-SHA256)
     * 2. mTLS client certificate identity (extracted at connection time)
     * 3. CLI-configured agent ID (static fallback, lowest trust)
     */
    val resolvedAgentId: String?
        get() = outputs.getOrNull(SignatureKey)?.actorId
            ?: connectionIdentity?.actorId
            ?: config.params.agentId

    fun requirePolicyDecision(): PolicyDecision =
        checkNotNull(policyDecision) { "policyDecision accessed before policy evaluation phase" }

    fun toPolicyRequest(): PolicyRequest = PolicyRequest(
        scheme = target.scheme, host = target.host, port = target.port,
        method = request.method, path = target.path, headers = request.headers
    )
}

data class RelayOutcome(
    val statusCode: Int,
    val bytesOut: Long = 0,
    val bytesIn: Long = 0,
    val redirectChain: List<AuditRedirectHop> = emptyList(),
    val retryCount: Int? = null,
    val responseRewrites: List<AuditResponseRewrite>? = null,
    val tokenUsage: AuditTokenUsage? = null
)

fun logAudit(
    context: RequestPipelineContext,
    decision: PolicyDecision,
    outcome: RelayOutcome,
    extras: AuditExtras = AuditExtras(),
    structuredPayload: AuditStructuredPayload? = null,
    webSocketSession: AuditWebSocketSession? = null
) = context.emitAudit.emit(
    buildAuditEvent(context, decision, outcome, extras, structuredPayload, webSocketSession)
)

private fun buildAuditEvent(
    context: RequestPipelineContext,
    decision: PolicyDecision,
    outcome: RelayOutcome,
    extras: AuditExtras,
    structuredPayload: AuditStructuredPayload?,
    webSocketSession: AuditWebSocketSession?
): AuditEvent {
    val effSecretIds = extras.secretIds.ifEmpty { context.injection.secretIds }
    val effInjectionAttempted = extras.injectionAttempted || context.injection.attemptedIds.isNotEmpty()
    val effSecretVersions = extras.secretVersions.ifEmpty { context.injection.secretVersions }
    val effResolvedIps = extras.resolvedIps ?: context.resolvedIps
    val effTags = extras.tags ?: context.matchedTags
    val effAgentProfileId = extras.agentProfileId ?: context.agentProfileId
    val phaseTimings = context.profiler.finish().toAuditMap().takeIf { it.isNotEmpty() }
    val dryRunOverride = (context.dryRun && decision.action == PolicyAction.DENY).takeIf { it }

    return AuditEvent(
        oagVersion = context.config.params.oagVersion,
        policyHash = context.policyHash,
        agentId = context.resolvedAgentId,
        sessionId = context.config.params.sessionId,
        requestId = context.outputs.getOrNull(RequestIdKey)?.value,
        trace = context.trace,
        request = AuditRequest(
            host = context.target.host,
            port = context.target.port,
            scheme = context.target.scheme,
            method = context.request.method,
            path = context.target.path,
            bytesOut = outcome.bytesOut,
            resolvedIps = effResolvedIps.map { it.hostAddress }
        ),
        response = AuditResponse(
            bytesIn = outcome.bytesIn,
            status = outcome.statusCode
        ),
        decision = AuditDecision(
            action = decision.action.label(),
            ruleId = decision.ruleId,
            reasonCode = decision.effectiveReasonCode()
        ),
        secrets = AuditSecrets(
            injectionAttempted = effInjectionAttempted,
            injected = effSecretIds.isNotEmpty(),
            secretIds = effSecretIds,
            secretVersions = effSecretVersions
        ),
        contentInspection = extras.contentInspection?.let { ci ->
            val pdr = context.pluginDetectionResult
            if (pdr == null) ci
            else ci.copy(
                pluginDetectorIds = pdr.detectorIds.takeIf { it.isNotEmpty() },
                pluginFindingCount = pdr.findings.size
            )
        } ?: context.pluginDetectionResult?.let { pdr ->
            AuditContentInspection(
                pluginDetectorIds = pdr.detectorIds.takeIf { it.isNotEmpty() },
                pluginFindingCount = pdr.findings.size
            )
        },
        headerRewrites = context.outputs.getOrNull(HeaderRewritesKey),
        retryCount = outcome.retryCount,
        tags = effTags?.takeIf { it.isNotEmpty() },
        redirectChain = outcome.redirectChain,
        responseRewrites = outcome.responseRewrites,
        structuredPayload = structuredPayload,
        webSocketSession = webSocketSession,
        agentProfile = effAgentProfileId,
        phaseTimings = phaseTimings,
        dryRunOverride = dryRunOverride,
        tokenUsage = outcome.tokenUsage
    )
}

fun <T> PhaseOutcome<T>.orDeny(): T = when (this) {
    is PhaseOutcome.Continue -> value
    is PhaseOutcome.Deny -> throw OagRequestException.PolicyDenied(
        decision = decision,
        status = statusCode,
        extras = auditExtras,
        errorResponse = errorResponse,
        enforcementActions = enforcementActions
    )
}

/**
 * Like [orDeny] but in dry-run mode, logs the deny and returns null instead of throwing.
 * Use this for phases where execution should continue in dry-run mode.
 */
fun <T> PhaseOutcome<T>.orDenyDryRunnable(context: RequestPipelineContext): T? = when (this) {
    is PhaseOutcome.Continue -> value
    is PhaseOutcome.Deny -> {
        if (!context.dryRun) {
            throw OagRequestException.PolicyDenied(
                decision = decision,
                status = statusCode,
                extras = auditExtras,
                errorResponse = errorResponse,
                enforcementActions = enforcementActions
            )
        }
        logAudit(context, decision, RelayOutcome(statusCode = statusCode.code), auditExtras)
        null
    }
}
