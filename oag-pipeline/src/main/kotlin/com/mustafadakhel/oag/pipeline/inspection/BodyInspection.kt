package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.injection.InjectionClassifier
import com.mustafadakhel.oag.inspection.content.detectStructuredPayload
import com.mustafadakhel.oag.policy.core.StructuredPayload
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.evaluation.matchesBody
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.BodyBufferKey
import com.mustafadakhel.oag.pipeline.BodyBufferResult
import com.mustafadakhel.oag.pipeline.DnsExfiltrationKey
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseKey
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.DEFAULT_BODY_BUFFER_LIMIT
import com.mustafadakhel.oag.pipeline.AuditEnrichable
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.pipeline.WebhookPayloadKeys
import com.mustafadakhel.oag.pipeline.webhookData
import com.mustafadakhel.oag.pipeline.DEFAULT_DENY_THRESHOLD
import com.mustafadakhel.oag.pipeline.denyPhase
import com.mustafadakhel.oag.pipeline.relay.bufferRequestBody

private const val ESCALATION_BOOST_FACTOR = 1.5

private fun buildInspectionDenyExtras(
    context: RequestPipelineContext,
    contentInspection: AuditContentInspection
) = AuditExtras(
    contentInspection = contentInspection,
    tags = context.matchedTags,
    agentProfileId = context.agentProfileId
)

private fun dnsEntropyScore(context: RequestPipelineContext): Double? =
    context.outputs.getOrNull(DnsExfiltrationKey)?.maxEntropy

class BodyBufferPhase(
    private val policyService: PolicyService
) : GatePhase, AuditEnrichable {
    override val stage = PipelineStage.INSPECT
    override val name = "body_buffer"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        bufferAndMatchBodyPhase(context, policyService)

    override fun enrichAudit(context: RequestPipelineContext) {
        val bufferableLength = resolveBufferableContentLength(context, policyService) ?: return
        bufferBody(context, bufferableLength)
    }
}

class ContentInspectionPhase(
    private val policyService: PolicyService,
    private val sessionRequestTracker: SessionRequestTracker?,
    private val mlClassifier: InjectionClassifier? = null
) : GatePhase, AuditEnrichable {
    companion object : PhaseKey<ContentInspectionResult>
    override val stage = PipelineStage.INSPECT
    override val name = "content_inspection"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkContentInspectionPhase(context, policyService, sessionRequestTracker, mlClassifier)
            .applySuppressionIfDenied(context, policyService, FindingType.PROMPT_INJECTION, "builtin:content_inspection")

    override fun enrichAudit(context: RequestPipelineContext) {
        val bodyText = context.bufferedBodyText ?: return
        val defaults = policyService.current.defaults
        val config = resolveContentInspection(context.matchedRule, defaults) ?: return
        val result = checkContentInspection(bodyText, config, policyService, mlClassifier) { msg -> context.debugLog { msg } }
        context.outputs.put(ContentInspectionPhase, result)
    }
}

class CredentialsPhase(
    private val policyService: PolicyService
) : GatePhase, AuditEnrichable {
    companion object : PhaseKey<List<String>>
    override val stage = PipelineStage.INSPECT
    override val name = "credentials"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkCredentialsPhase(context, policyService)
            .applySuppressionIfDenied(context, policyService, FindingType.CREDENTIAL, "builtin:credentials")

    override fun enrichAudit(context: RequestPipelineContext) {
        val bodyText = context.bufferedBodyText ?: return
        if (!resolveCredentialDetection(context.matchedRule, policyService.current.defaults)) return
        val creds = checkOutboundCredentials(bodyText)
        if (creds.isNotEmpty()) context.outputs.put(CredentialsPhase, creds)
    }
}

class DataClassificationPhase(
    private val policyService: PolicyService
) : GatePhase, AuditEnrichable {
    companion object : PhaseKey<DataClassificationResult>
    override val stage = PipelineStage.INSPECT
    override val name = "data_classification"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkDataClassificationPhase(context, policyService)
            .applySuppressionIfDenied(context, policyService, FindingType.PII, "builtin:data_classification")

    override fun enrichAudit(context: RequestPipelineContext) {
        val bodyText = context.bufferedBodyText ?: return
        val defaults = policyService.current.defaults
        val config = resolveDataClassification(context.matchedRule, defaults) ?: return
        val result = checkDataClassification(bodyText, config) { msg -> context.debugLog { msg } }
        context.outputs.put(DataClassificationPhase, result)
    }
}

internal fun PhaseOutcome<Unit>.applySuppressionIfDenied(
    context: RequestPipelineContext,
    policyService: PolicyService,
    findingType: FindingType,
    source: String
): PhaseOutcome<Unit> {
    if (this is PhaseOutcome.Continue) return this
    val suppressions = context.matchedRule?.findingSuppressions
        ?: policyService.current.defaults?.findingSuppressions
    if (suppressions.isNullOrEmpty()) return this
    val syntheticFinding = Finding(
        type = findingType,
        severity = FindingSeverity.HIGH,
        confidence = 1.0,
        location = FindingLocation.Body,
        evidence = mapOf(EvidenceKey.SOURCE to source),
        recommendedActions = listOf(RecommendedAction.DENY)
    )
    val result = suppressFindings(listOf(syntheticFinding), suppressions, context.target.host)
    return if (result.suppressed.isNotEmpty()) PhaseOutcome.Continue(Unit) else this
}

private inline fun <T> resolveInspectionConfig(
    skip: Boolean,
    ruleLevel: T?,
    defaultLevel: T?,
    isActive: (T) -> Boolean
): T? {
    if (skip) return null
    if (ruleLevel != null) return ruleLevel.takeIf(isActive)
    return defaultLevel?.takeIf(isActive)
}

fun resolveContentInspection(rule: PolicyRule?, defaults: PolicyDefaults?): PolicyContentInspection? =
    resolveInspectionConfig(
        skip = rule?.skipContentInspection == true,
        ruleLevel = rule?.contentInspection,
        defaultLevel = defaults?.contentInspection
    ) { it.enableBuiltinPatterns == true || !it.customPatterns.isNullOrEmpty() || !it.anchoredPatterns.isNullOrEmpty() }

fun resolveCredentialDetection(rule: PolicyRule?, defaults: PolicyDefaults?): Boolean {
    if (rule?.skipOutboundCredentialDetection == true) return false
    return defaults?.outboundCredentialDetection == true
}

fun resolveDataClassification(rule: PolicyRule?, defaults: PolicyDefaults?): PolicyDataClassification? =
    resolveInspectionConfig(
        skip = rule?.skipDataClassification == true,
        ruleLevel = rule?.dataClassification,
        defaultLevel = defaults?.dataClassification
    ) { it.enableBuiltinPatterns == true || !it.customPatterns.isNullOrEmpty() }

fun resolveResponseDataClassification(rule: PolicyRule?, defaults: PolicyDefaults?): PolicyDataClassification? {
    if (rule?.skipDataClassification == true) return null
    val config = rule?.dataClassification ?: defaults?.dataClassification ?: return null
    if (config.scanResponses != true) return null
    if (config.enableBuiltinPatterns != true && config.customPatterns.isNullOrEmpty()) return null
    return config
}

fun resolveStreamingScanEnabled(rule: PolicyRule?, defaults: PolicyDefaults?): Boolean {
    rule?.contentInspection?.scanStreamingResponses?.let { return it }
    defaults?.contentInspection?.scanStreamingResponses?.let { return it }
    defaults?.scanStreamingResponses?.let { return it }
    return true
}

fun bufferAndMatchBodyPhase(
    context: RequestPipelineContext,
    policyService: PolicyService
): PhaseOutcome<Unit> {
    val bufferableLength = resolveBufferableContentLength(context, policyService)
        ?: return PhaseOutcome.Continue(Unit)

    bufferBody(context, bufferableLength)
    return evaluateBodyMatch(context)
}

private fun resolveBufferableContentLength(
    context: RequestPipelineContext,
    policyService: PolicyService
): Long? {
    val rule = context.matchedRule ?: return null
    val defaults = policyService.current.defaults
    val pluginConfig = rule.pluginDetection ?: defaults?.pluginDetection
    val pluginDetectionActive = pluginConfig != null &&
        rule.skipPluginDetection != true &&
        pluginConfig.enabled != false
    val needsBuffer = rule.bodyMatch != null ||
        resolveContentInspection(rule, defaults) != null ||
        pluginDetectionActive
    if (!needsBuffer) return null

    val contentLength = context.request.headers[HttpConstants.CONTENT_LENGTH]?.toLongOrNull()
    val maxBodyBytes = rule.maxBodyBytes ?: defaults?.maxBodyBytes ?: DEFAULT_BODY_BUFFER_LIMIT
    // Requests without Content-Length (chunked/connection-close) cannot be buffered.
    // Per RFC 7230, no Content-Length + no Transfer-Encoding = zero-length body.
    if (contentLength == null || contentLength <= 0) {
        if (contentLength == null) {
            context.debugLog { "body inspection skipped: no Content-Length for ${context.target.host}${context.target.path}" }
        }
        return null
    }
    if (contentLength > maxBodyBytes) return null // handled by checkBodySizePhase
    return contentLength
}

private fun bufferBody(
    context: RequestPipelineContext,
    contentLength: Long
) {
    val clientInput = requireNotNull(context.clientInput) { "clientInput must be set before body buffering phase" }
    val bufferedBody = bufferRequestBody(clientInput, contentLength)
    val bufferedBodyText = bufferedBody.toString(Charsets.UTF_8)
    val detectedPayload = detectStructuredPayload(
        bufferedBodyText,
        context.request.headers[HttpConstants.CONTENT_TYPE]
    )
    context.outputs.put(BodyBufferKey, BodyBufferResult(
        body = bufferedBody,
        bodyText = bufferedBodyText,
        structuredPayload = detectedPayload
    ))
}

private fun evaluateBodyMatch(
    context: RequestPipelineContext
): PhaseOutcome<Unit> {
    val bodyText = context.bufferedBodyText ?: return PhaseOutcome.Continue(Unit)
    val bodyMatch = context.matchedRule?.bodyMatch ?: return PhaseOutcome.Continue(Unit)
    if (!matchesBody(bodyMatch, bodyText) { msg -> context.debugLog { msg } }) {
        context.debugLog { "body match failed rule=${context.policyDecision?.ruleId}" }
        return context.denyPhase(ReasonCode.BODY_MATCH_FAILED)
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkContentInspectionPhase(
    context: RequestPipelineContext,
    policyService: PolicyService,
    sessionRequestTracker: SessionRequestTracker?,
    mlClassifier: InjectionClassifier? = null
): PhaseOutcome<Unit> {
    val bodyText = context.bufferedBodyText ?: run {
        context.debugLog { "content inspection skipped: no buffered body for ${context.target.host}${context.target.path}" }
        return PhaseOutcome.Continue(Unit)
    }
    val defaults = policyService.current.defaults
    val effectiveContentInspection = resolveContentInspection(context.matchedRule, defaults) ?: run {
        context.debugLog { "content inspection skipped: no inspection config for ${context.target.host}" }
        return PhaseOutcome.Continue(Unit)
    }

    val inspectionResult = checkContentInspection(bodyText, effectiveContentInspection, policyService, mlClassifier) { msg -> context.debugLog { msg } }

    val sessionId = context.config.params.sessionId
    val injScore = inspectionResult.injectionScore
    if (sessionId != null && sessionRequestTracker != null && injScore != null) {
        sessionRequestTracker.recordInjectionScore(sessionId, injScore)
    }

    val escalating = if (sessionId != null && sessionRequestTracker != null) {
        sessionRequestTracker.injectionTrend(sessionId).escalating
    } else false

    val effectiveResult = if (escalating && inspectionResult.decision == null && injScore != null) {
        val boostedScore = minOf(injScore * ESCALATION_BOOST_FACTOR, 1.0)
        val scoringConfig = policyService.current.defaults?.injectionScoring
        val denyThreshold = scoringConfig?.denyThreshold ?: DEFAULT_DENY_THRESHOLD
        if (boostedScore >= denyThreshold) {
            context.debugLog { "injection escalation detected: boosted score ${"%.3f".format(boostedScore)} >= threshold $denyThreshold" }
            inspectionResult.copy(
                decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.INJECTION_DETECTED),
                injectionScore = boostedScore,
                injectionSignals = inspectionResult.injectionSignals + "escalation_boost"
            )
        } else inspectionResult
    } else inspectionResult

    context.outputs.put(ContentInspectionPhase, effectiveResult)

    val inspDecision = effectiveResult.decision
    if (inspDecision != null) {
        context.debugLog { "injection detected in request body" }
        return PhaseOutcome.Deny(
            decision = inspDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = buildInspectionDenyExtras(context, AuditContentInspection(
                bodyInspected = true,
                injectionPatternsMatched = effectiveResult.matchedPatterns.ifEmpty { null },
                dnsEntropyScore = dnsEntropyScore(context),
                injectionScore = effectiveResult.injectionScore,
                injectionSignals = effectiveResult.injectionSignals.ifEmpty { null },
                injectionEscalating = escalating.takeIf { it }
            )),
            enforcementActions = listOf(
                EnforcementAction.Notify(
                    message = WebhookPayloadKeys.EVENT_INJECTION_DETECTED,
                    data = mapOf(WebhookPayloadKeys.DATA_PATTERNS to inspectionResult.matchedPatterns)
                )
            )
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkCredentialsPhase(
    context: RequestPipelineContext,
    policyService: PolicyService
): PhaseOutcome<Unit> {
    val bodyText = context.bufferedBodyText ?: run {
        context.debugLog { "credential detection skipped: no buffered body for ${context.target.host}${context.target.path}" }
        return PhaseOutcome.Continue(Unit)
    }
    val credentialDetectionEnabled = resolveCredentialDetection(context.matchedRule, policyService.current.defaults)
    if (!credentialDetectionEnabled) return PhaseOutcome.Continue(Unit)

    val creds = checkOutboundCredentials(bodyText)
    if (creds.isNotEmpty()) {
        context.outputs.put(CredentialsPhase, creds)
        val credDecision = PolicyDecision(
            action = PolicyAction.DENY,
            ruleId = context.policyDecision?.ruleId,
            reasonCode = ReasonCode.OUTBOUND_CREDENTIAL_DETECTED
        )
        context.debugLog { "outbound credential detected" }
        return PhaseOutcome.Deny(
            decision = credDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = buildInspectionDenyExtras(context, AuditContentInspection(
                bodyInspected = true,
                dnsEntropyScore = dnsEntropyScore(context),
                credentialsDetected = creds
            )),
            enforcementActions = listOf(
                EnforcementAction.Notify(
                    message = WebhookPayloadKeys.EVENT_CREDENTIAL_DETECTED,
                    data = mapOf(WebhookPayloadKeys.DATA_CREDENTIALS to creds)
                )
            )
        )
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkDataClassificationPhase(
    context: RequestPipelineContext,
    policyService: PolicyService
): PhaseOutcome<Unit> {
    val bodyText = context.bufferedBodyText ?: run {
        context.debugLog { "data classification skipped: no buffered body for ${context.target.host}${context.target.path}" }
        return PhaseOutcome.Continue(Unit)
    }
    val defaults = policyService.current.defaults
    val effectiveDataClassification = resolveDataClassification(context.matchedRule, defaults) ?: run {
        context.debugLog { "data classification skipped: no classification config for ${context.target.host}" }
        return PhaseOutcome.Continue(Unit)
    }

    val result = checkDataClassification(bodyText, effectiveDataClassification) { msg -> context.debugLog { msg } }
    context.outputs.put(DataClassificationPhase, result)
    val classDecision = result.decision
    if (classDecision != null) {
        context.debugLog { "sensitive data detected in request body" }
        return PhaseOutcome.Deny(
            decision = classDecision,
            statusCode = HttpStatus.FORBIDDEN,
            auditExtras = buildInspectionDenyExtras(context, AuditContentInspection(
                bodyInspected = true,
                dnsEntropyScore = dnsEntropyScore(context),
                dataClassificationMatches = result.matches.ifEmpty { null },
                dataClassificationCategories = result.categories.ifEmpty { null }
            ))
        )
    }
    return PhaseOutcome.Continue(Unit)
}
