package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.audit.AuditContentInspection
import com.mustafadakhel.oag.audit.AuditStructuredPayload
import com.mustafadakhel.oag.audit.AuditTokenUsage
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.pipeline.BodyBufferKey
import com.mustafadakhel.oag.pipeline.DnsExfiltrationKey
import com.mustafadakhel.oag.pipeline.FindingAuditKey
import com.mustafadakhel.oag.pipeline.FindingRedactionKey
import com.mustafadakhel.oag.pipeline.PluginDetectionKey
import com.mustafadakhel.oag.pipeline.inspection.ContentInspectionPhase
import com.mustafadakhel.oag.pipeline.inspection.CredentialsPhase
import com.mustafadakhel.oag.pipeline.inspection.DataClassificationPhase
import com.mustafadakhel.oag.pipeline.inspection.ResponseRelayResult
import com.mustafadakhel.oag.pipeline.network.PathAnalysisPhase
import com.mustafadakhel.oag.pipeline.network.UrlExfiltrationPhase
import com.mustafadakhel.oag.pipeline.phase.DataBudgetPhase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext

internal fun recordAndBuildTokenUsage(
    relayResult: ResponseRelayResult,
    sessionId: String?,
    policyService: PolicyService,
    tokenBudgetTracker: TokenBudgetTracker
): AuditTokenUsage? = relayResult.tokenUsage?.let { tu ->
    if (sessionId != null) {
        val limit = policyService.current.defaults?.maxTokensPerSession
        if (limit != null) tokenBudgetTracker.recordAndCheck(sessionId, tu.totalTokens, limit)
    }
    AuditTokenUsage(promptTokens = tu.promptTokens, completionTokens = tu.completionTokens, totalTokens = tu.totalTokens)
}

internal fun RequestPipelineContext.buildAuditPayload(): AuditStructuredPayload? =
    outputs.getOrNull(BodyBufferKey)?.structuredPayload?.let {
        AuditStructuredPayload(
            protocol = it.protocol.protocolId,
            method = it.method,
            operationName = it.operationName,
            operationType = it.operationType?.label()
        )
    }

private fun AuditContentInspection.isNonTrivial(): Boolean =
    bodyInspected || injectionPatternsMatched != null || urlEntropyScore != null ||
        dnsEntropyScore != null || dataBudgetUsedBytes != null || responseTruncated ||
        streamingPatternsMatched != null || injectionScore != null || injectionSignals != null ||
        credentialsDetected != null || dataClassificationMatches != null ||
        dataClassificationCategories != null || pathEntropyScore != null || pathTraversalDetected != null

internal fun buildFinalContentInspection(
    context: RequestPipelineContext,
    relayResult: ResponseRelayResult
): AuditContentInspection? {
    val inspectionResult = context.outputs.getOrNull(ContentInspectionPhase)
    val urlExfilResult = context.outputs.getOrNull(UrlExfiltrationPhase)
    val dnsExfilResult = context.outputs.getOrNull(DnsExfiltrationKey)
    val dataBudgetUsedBytes = context.outputs.getOrNull(DataBudgetPhase)
    val credentialsDetected = context.outputs.getOrNull(CredentialsPhase)
    val dataClassResult = context.outputs.getOrNull(DataClassificationPhase)
    val pathAnalysis = context.outputs.getOrNull(PathAnalysisPhase)
    val pluginResult = context.outputs.getOrNull(PluginDetectionKey)
    val responsePlugins = relayResult.responsePluginFindings
    val responseDataClass = relayResult.responseDataClassification
    val redactFindings = context.outputs.getOrNull(FindingRedactionKey)
    val logFindings = context.outputs.getOrNull(FindingAuditKey)
    return AuditContentInspection(
        bodyInspected = inspectionResult != null,
        injectionPatternsMatched = inspectionResult?.matchedPatterns?.ifEmpty { null },
        urlEntropyScore = urlExfilResult?.maxEntropy,
        dnsEntropyScore = dnsExfilResult?.maxEntropy,
        dataBudgetUsedBytes = dataBudgetUsedBytes,
        responseTruncated = relayResult.truncationAction != null,
        streamingPatternsMatched = relayResult.streamingMatchedPatterns.ifEmpty { null },
        injectionScore = inspectionResult?.injectionScore,
        injectionSignals = inspectionResult?.injectionSignals?.ifEmpty { null },
        credentialsDetected = credentialsDetected,
        dataClassificationMatches = dataClassResult?.matches?.ifEmpty { null },
        dataClassificationCategories = dataClassResult?.categories?.ifEmpty { null },
        pathEntropyScore = pathAnalysis?.pathEntropyScore,
        pathTraversalDetected = pathAnalysis?.pathTraversalDetected?.takeIf { it },
        suppressedFindingCount = pluginResult?.suppressedCount?.takeIf { it > 0 },
        pluginDetectorIds = pluginResult?.detectorIds?.ifEmpty { null },
        pluginFindingCount = pluginResult?.findings?.size?.takeIf { it > 0 },
        responsePluginDetectorIds = responsePlugins?.detectorIds?.ifEmpty { null },
        responsePluginFindingCount = responsePlugins?.findings?.size?.takeIf { it > 0 },
        responseDataClassificationMatches = responseDataClass?.matches?.ifEmpty { null },
        responseDataClassificationCategories = responseDataClass?.categories?.ifEmpty { null },
        redactFindingCount = redactFindings?.size?.takeIf { it > 0 },
        logFindingCount = logFindings?.size?.takeIf { it > 0 },
        streamingPluginDetectorIds = relayResult.streamingPluginFindings?.detectorIds?.ifEmpty { null },
        streamingPluginFindingCount = relayResult.streamingPluginFindings?.findings?.size?.takeIf { it > 0 }
    ).takeIf { it.isNonTrivial() }
}
