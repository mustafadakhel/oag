package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.StageSet
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.pipeline.inspection.BodyBufferPhase
import com.mustafadakhel.oag.pipeline.inspection.ContentInspectionPhase
import com.mustafadakhel.oag.pipeline.inspection.CredentialsPhase
import com.mustafadakhel.oag.pipeline.inspection.DataClassificationPhase
import com.mustafadakhel.oag.pipeline.inspection.PluginDetectionPhase
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.pipeline.network.DnsExfiltrationPhase
import com.mustafadakhel.oag.pipeline.network.DnsResolutionCheckPhase
import com.mustafadakhel.oag.pipeline.network.DnsResolutionPhase
import com.mustafadakhel.oag.pipeline.network.IpBlockPhase
import com.mustafadakhel.oag.pipeline.network.PathAnalysisPhase
import com.mustafadakhel.oag.pipeline.network.PathValidationPhase
import com.mustafadakhel.oag.pipeline.network.ResolvedIpBlockPhase
import com.mustafadakhel.oag.pipeline.network.UrlExfiltrationPhase
import com.mustafadakhel.oag.pipeline.phase.AgentProfilePhase
import com.mustafadakhel.oag.pipeline.phase.BodySizePhase
import com.mustafadakhel.oag.pipeline.phase.CircuitBreakerPhase
import com.mustafadakhel.oag.pipeline.phase.ConnectPolicyEvalPhase
import com.mustafadakhel.oag.pipeline.phase.DataBudgetPhase
import com.mustafadakhel.oag.pipeline.phase.MitmPolicyEvalPhase
import com.mustafadakhel.oag.pipeline.phase.HeaderRewritesPhase
import com.mustafadakhel.oag.pipeline.phase.PolicyEvalPhase
import com.mustafadakhel.oag.pipeline.phase.PrepareHeadersMitmPhase
import com.mustafadakhel.oag.pipeline.phase.PrepareHeadersPhase
import com.mustafadakhel.oag.pipeline.phase.RateLimitPhase
import com.mustafadakhel.oag.pipeline.phase.RequestIdHeaderPhase
import com.mustafadakhel.oag.pipeline.phase.RequestIdPhase
import com.mustafadakhel.oag.pipeline.phase.SecretInjectionFallbackPhase
import com.mustafadakhel.oag.pipeline.phase.SecretInjectionPhase
import com.mustafadakhel.oag.pipeline.phase.SignaturePhase
import com.mustafadakhel.oag.pipeline.phase.TokenBudgetPhase
import com.mustafadakhel.oag.pipeline.phase.TransferEncodingPhase
import com.mustafadakhel.oag.pipeline.phase.VelocitySpikePhase
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.inspection.injection.InjectionClassifier
import com.mustafadakhel.oag.secrets.SecretMaterializer

fun buildHttpPipeline(
    config: HandlerConfig,
    policyService: PolicyService,
    hostResolver: HostResolver,
    rateLimiterRegistry: RateLimiterRegistry,
    sessionRequestTracker: SessionRequestTracker?,
    dataBudgetTracker: DataBudgetTracker,
    tokenBudgetTracker: TokenBudgetTracker,
    secretMaterializer: SecretMaterializer,
    circuitBreakerRegistry: CircuitBreakerRegistry?,
    detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    mlClassifier: InjectionClassifier? = null
): Pipeline = Pipeline(name = "http", stageSet = StageSet.REQUEST, phases = buildList {
    if (config.requestId.injectRequestId) add(RequestIdPhase())
    if (sessionRequestTracker != null) add(VelocitySpikePhase(sessionRequestTracker))
    if (config.security.agentSigningSecret != null) add(SignaturePhase())
    add(DnsExfiltrationPhase(policyService))
    if (config.network.blockIpLiterals) add(IpBlockPhase())
    add(DnsResolutionPhase(policyService, hostResolver))
    if (config.network.blockPrivateResolvedIps) add(ResolvedIpBlockPhase())
    add(DnsResolutionCheckPhase(policyService))
    add(PathValidationPhase())
    if (circuitBreakerRegistry != null) add(CircuitBreakerPhase(circuitBreakerRegistry))
    add(PolicyEvalPhase(policyService))
    add(RateLimitPhase(rateLimiterRegistry))
    add(AgentProfilePhase(rateLimiterRegistry))
    add(BodyBufferPhase(policyService))
    add(ContentInspectionPhase(policyService, sessionRequestTracker, mlClassifier))
    add(CredentialsPhase(policyService))
    add(DataClassificationPhase(policyService))
    if (detectorRegistry.allRegistrations().isNotEmpty()) {
        add(PluginDetectionPhase(detectorRegistry, policyService))
    }
    add(UrlExfiltrationPhase(policyService))
    add(PathAnalysisPhase(policyService))
    add(DataBudgetPhase(policyService, dataBudgetTracker))
    add(TokenBudgetPhase(policyService, tokenBudgetTracker))
    add(PrepareHeadersPhase())
    add(TransferEncodingPhase())
    add(BodySizePhase(policyService))
    add(SecretInjectionPhase(policyService, secretMaterializer))
    add(SecretInjectionFallbackPhase())
    add(HeaderRewritesPhase())
    if (config.requestId.injectRequestId) add(RequestIdHeaderPhase())
})

fun buildConnectPipeline(
    config: HandlerConfig,
    policyService: PolicyService,
    hostResolver: HostResolver,
    rateLimiterRegistry: RateLimiterRegistry,
    sessionRequestTracker: SessionRequestTracker?,
    circuitBreakerRegistry: CircuitBreakerRegistry?
): Pipeline = Pipeline(name = "connect", stageSet = StageSet.CONNECT, phases = buildList {
    if (sessionRequestTracker != null) add(VelocitySpikePhase(sessionRequestTracker))
    if (config.security.agentSigningSecret != null) add(SignaturePhase())
    add(DnsExfiltrationPhase(policyService))
    if (config.network.blockIpLiterals) add(IpBlockPhase())
    add(DnsResolutionPhase(policyService, hostResolver))
    if (config.network.blockPrivateResolvedIps) add(ResolvedIpBlockPhase())
    add(DnsResolutionCheckPhase(policyService))
    if (circuitBreakerRegistry != null) add(CircuitBreakerPhase(circuitBreakerRegistry))
    add(ConnectPolicyEvalPhase(policyService))
    add(RateLimitPhase(rateLimiterRegistry))
    add(AgentProfilePhase(rateLimiterRegistry))
})

// Uses StageSet.REQUEST (all stages) despite only containing IDENTITY and TARGET phases.
// The full set is harmless — it matches the HTTP pipeline convention and the stage ordering
// validation still enforces non-decreasing order. These phases run on decrypted inner HTTP
// requests before policy evaluation; IDENTITY and TARGET were not handled by the outer
// CONNECT pipeline for the inner request's path/signature.
fun buildMitmPrePolicyPipeline(
    config: HandlerConfig,
    policyService: PolicyService
): Pipeline = Pipeline(name = "mitm-pre-policy", stageSet = StageSet.REQUEST, phases = buildList {
    if (config.security.agentSigningSecret != null) add(SignaturePhase())
    add(DnsExfiltrationPhase(policyService))
    add(PathValidationPhase())
})

fun buildMitmPipeline(
    policyService: PolicyService,
    rateLimiterRegistry: RateLimiterRegistry,
    sessionRequestTracker: SessionRequestTracker?,
    dataBudgetTracker: DataBudgetTracker,
    tokenBudgetTracker: TokenBudgetTracker,
    secretMaterializer: SecretMaterializer,
    circuitBreakerRegistry: CircuitBreakerRegistry? = null,
    detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    mlClassifier: InjectionClassifier? = null
): Pipeline = Pipeline(name = "mitm", stageSet = StageSet.REQUEST, phases = buildList {
    add(RequestIdPhase())
    if (sessionRequestTracker != null) add(VelocitySpikePhase(sessionRequestTracker))
    if (circuitBreakerRegistry != null) add(CircuitBreakerPhase(circuitBreakerRegistry))
    add(MitmPolicyEvalPhase(policyService))
    add(RateLimitPhase(rateLimiterRegistry))
    add(AgentProfilePhase(rateLimiterRegistry))
    add(BodyBufferPhase(policyService))
    add(ContentInspectionPhase(policyService, sessionRequestTracker, mlClassifier))
    add(CredentialsPhase(policyService))
    add(DataClassificationPhase(policyService))
    if (detectorRegistry.allRegistrations().isNotEmpty()) {
        add(PluginDetectionPhase(detectorRegistry, policyService))
    }
    add(UrlExfiltrationPhase(policyService))
    add(PathAnalysisPhase(policyService))
    add(DataBudgetPhase(policyService, dataBudgetTracker))
    add(TokenBudgetPhase(policyService, tokenBudgetTracker))
    add(PrepareHeadersMitmPhase())
    add(TransferEncodingPhase())
    add(BodySizePhase(policyService))
    add(SecretInjectionPhase(policyService, secretMaterializer))
    add(SecretInjectionFallbackPhase())
    add(HeaderRewritesPhase())
    add(RequestIdHeaderPhase())
})

