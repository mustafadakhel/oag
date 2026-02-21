package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.inspection.DnsLabel
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.HeaderEntry
import com.mustafadakhel.oag.inspection.Headers
import com.mustafadakhel.oag.inspection.InspectableArtifact
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.TextBody
import com.mustafadakhel.oag.inspection.Url
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.FindingAuditKey
import com.mustafadakhel.oag.pipeline.FindingRedactionKey
import com.mustafadakhel.oag.pipeline.AuditEnrichable
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PluginDetectionKey
import com.mustafadakhel.oag.pipeline.PluginDetectionResult
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.denyPhase
import com.mustafadakhel.oag.policy.core.PolicyPluginDetection
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

class PluginDetectionPhase(
    private val registry: DetectorRegistry,
    private val policyService: PolicyService
) : GatePhase, AuditEnrichable {
    override val name = "plugin_detection"
    override val stage = PipelineStage.INSPECT
    override val skipWhenPolicyDenied = true

    override fun enrichAudit(context: RequestPipelineContext) {
        if (context.matchedRule?.skipPluginDetection == true) return
        val defaults = policyService.current.defaults
        val pluginConfig = context.matchedRule?.pluginDetection ?: defaults?.pluginDetection
        if (pluginConfig?.enabled == false) return

        val inspectionContext = InspectionContext(
            host = context.target.host, method = context.request.method,
            path = context.target.path, ruleId = context.policyDecision?.ruleId,
            agentId = context.config.params.agentId
        )
        val matchedDetectorIds = mutableListOf<String>()
        val bodyText = context.bufferedBodyText
        val findings = buildList {
            if (bodyText != null) {
                addAll(runDetectors(registry.registrationsFor(TextBody::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) { TextBody(bodyText) })
            }
            addAll(runDetectors(registry.registrationsFor(Headers::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) { Headers(context.request.headers.map { (k, v) -> HeaderEntry(k, v) }) })
            addAll(runDetectors(registry.registrationsFor(Url::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) {
                val (urlPath, urlQuery) = splitPathQuery(context.target.path)
                Url(scheme = context.target.scheme, host = context.target.host, port = context.target.port, path = urlPath, query = urlQuery)
            })
            for (label in context.target.host.split('.')) {
                addAll(runDetectors(registry.registrationsFor(DnsLabel::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) { DnsLabel(label = label) })
            }
        }
        if (findings.isEmpty()) return
        val suppressions = context.matchedRule?.findingSuppressions ?: defaults?.findingSuppressions
        val keptFindings = suppressFindings(findings, suppressions, context.target.host).kept
        if (keptFindings.isNotEmpty()) {
            context.outputs.put(PluginDetectionKey, PluginDetectionResult(
                findings = keptFindings, detectorIds = matchedDetectorIds.distinct()
            ))
        }
    }

    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        if (context.matchedRule?.skipPluginDetection == true) return PhaseOutcome.Continue(Unit)
        val defaults = policyService.current.defaults
        val pluginConfig = context.matchedRule?.pluginDetection ?: defaults?.pluginDetection
        if (pluginConfig?.enabled == false) return PhaseOutcome.Continue(Unit)

        val inspectionContext = InspectionContext(
            host = context.target.host,
            method = context.request.method,
            path = context.target.path,
            ruleId = context.policyDecision?.ruleId,
            agentId = context.config.params.agentId
        )

        val matchedDetectorIds = mutableListOf<String>()
        val bodyText = context.bufferedBodyText
        val findings = buildList {
            if (bodyText != null) {
                addAll(runDetectors(registry.registrationsFor(TextBody::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) { TextBody(bodyText) })
            }
            addAll(runDetectors(registry.registrationsFor(Headers::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) { Headers(context.request.headers.map { (k, v) -> HeaderEntry(k, v) }) })
            addAll(runDetectors(registry.registrationsFor(Url::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) {
                val (urlPath, urlQuery) = splitPathQuery(context.target.path)
                Url(scheme = context.target.scheme, host = context.target.host, port = context.target.port, path = urlPath, query = urlQuery)
            })
            for (label in context.target.host.split('.')) {
                addAll(runDetectors(registry.registrationsFor(DnsLabel::class.java), pluginConfig, context, inspectionContext, matchedDetectorIds) {
                    DnsLabel(label = label)
                })
            }
        }
        if (findings.isEmpty()) return PhaseOutcome.Continue(Unit)

        val suppressions = context.matchedRule?.findingSuppressions
            ?: policyService.current.defaults?.findingSuppressions
        val suppressionResult = suppressFindings(findings, suppressions, context.target.host)
        val keptFindings = suppressionResult.kept
        if (keptFindings.isEmpty()) return PhaseOutcome.Continue(Unit)

        context.outputs.put(PluginDetectionKey, PluginDetectionResult(
            findings = keptFindings,
            detectorIds = matchedDetectorIds.distinct(),
            suppressedCount = suppressionResult.suppressed.size
        ))

        val severityThreshold = pluginConfig?.denySeverityThreshold?.let { raw ->
            FindingSeverity.entries.firstOrNull { it.name.equals(raw, ignoreCase = true) }
        }
        val denyFindings = keptFindings.filter { f ->
            f.recommendedActions.any { it == RecommendedAction.DENY } ||
                (severityThreshold != null && f.severity >= severityThreshold)
        }
        if (denyFindings.isNotEmpty()) {
            return context.denyPhase(
                reasonCode = ReasonCode.PLUGIN_DETECTED,
                auditExtras = AuditExtras(tags = context.matchedTags, agentProfileId = context.agentProfileId)
            )
        }
        val redactFindings = keptFindings.filter { f -> f.recommendedActions.any { it == RecommendedAction.REDACT } }
        if (redactFindings.isNotEmpty()) {
            context.outputs.put(FindingRedactionKey, redactFindings)
        }
        val logFindings = keptFindings.filter { f -> f.recommendedActions.any { it == RecommendedAction.LOG } }
        if (logFindings.isNotEmpty()) {
            context.outputs.put(FindingAuditKey, logFindings)
        }
        return PhaseOutcome.Continue(Unit)
    }

    private fun <T : InspectableArtifact> runDetectors(
        allRegistrations: List<DetectorRegistration<T>>,
        pluginConfig: PolicyPluginDetection?,
        context: RequestPipelineContext,
        inspectionContext: InspectionContext,
        matchedIds: MutableList<String>,
        artifactFactory: () -> T
    ): List<Finding> {
        val regs = filterByConfig(allRegistrations, pluginConfig)
        if (regs.isEmpty()) return emptyList()
        val artifact = artifactFactory()
        return regs.flatMap { reg ->
            val results = runCatching { reg.detector.inspect(artifact, inspectionContext) }
                .onFailure { e -> context.debugLog { "plugin detector '${reg.id}' failed: ${e.message}" } }
                .getOrDefault(emptyList())
            if (results.isNotEmpty()) matchedIds.add(reg.id)
            results
        }
    }
}

private fun <T : InspectableArtifact> filterByConfig(
    registrations: List<DetectorRegistration<T>>,
    config: PolicyPluginDetection?
): List<DetectorRegistration<T>> {
    if (config == null) return registrations
    val allowIds = config.detectorIds
    val excludeIds = config.excludeDetectorIds
    return registrations.filter { reg ->
        (allowIds == null || reg.id in allowIds) && (excludeIds == null || reg.id !in excludeIds)
    }
}

private fun splitPathQuery(path: String): Pair<String, String?> {
    val idx = path.indexOf('?')
    if (idx < 0) return path to null
    return path.substring(0, idx) to path.substring(idx + 1)
}
