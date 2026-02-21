package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.REDACTED_SENTINEL
import com.mustafadakhel.oag.audit.AuditResponseRewrite
import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RedactionPattern
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.pipeline.inspection.DataClassificationResult
import com.mustafadakhel.oag.pipeline.inspection.ResponseScanResult
import com.mustafadakhel.oag.pipeline.inspection.checkDataClassification
import com.mustafadakhel.oag.pipeline.inspection.scanResponseBody
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite
import com.mustafadakhel.oag.policy.core.ResponseRewriteAction
import com.mustafadakhel.oag.policy.evaluation.matchesBody

data class RedactionResult(
    val transformedText: String,
    val actions: List<EnforcementAction.Redact>,
    val auditEntries: List<AuditResponseRewrite>
)

fun applyPolicyRedactions(
    bodyText: String,
    rewrites: List<PolicyResponseRewrite>,
    onError: (String) -> Unit
): RedactionResult {
    var text = bodyText
    val actions = mutableListOf<EnforcementAction.Redact>()
    val auditEntries = mutableListOf<AuditResponseRewrite>()
    rewrites.filterIsInstance<PolicyResponseRewrite.Redact>().forEach { rw ->
        val regex = runCatching { cachedRegex(rw.pattern) }
            .onFailure { e -> onError("redaction regex failed pattern=${rw.pattern}: ${e.message}") }
            .getOrNull() ?: return@forEach
        val replacement = rw.replacement ?: REDACTED_SENTINEL
        var count = 0
        text = regex.replace(text) { count++; replacement }
        if (count > 0) {
            actions.add(EnforcementAction.Redact(target = rw.pattern))
            auditEntries.add(AuditResponseRewrite(
                action = ResponseRewriteAction.REDACT.label(),
                pattern = rw.pattern,
                redactionCount = count
            ))
        }
    }
    return RedactionResult(text, actions, auditEntries)
}

fun evaluateBodyMatch(
    bodyText: String,
    bodyMatch: PolicyBodyMatch?,
    onError: (String) -> Unit
): Boolean =
    bodyMatch == null || matchesBody(bodyMatch, bodyText, onError)

fun runResponsePluginScan(
    bodyText: String,
    statusCode: Int,
    contentType: String?,
    ruleHost: String?,
    ruleId: String?,
    registry: DetectorRegistry,
    onError: (String) -> Unit
): ResponseScanResult =
    scanResponseBody(bodyText, statusCode, contentType, registry, InspectionContext(host = ruleHost, ruleId = ruleId), onError)

fun applyFindingRedactions(
    bodyText: String,
    patterns: List<RedactionPattern>
): RedactionResult {
    var text = bodyText
    val actions = mutableListOf<EnforcementAction.Redact>()
    for (rp in patterns) {
        var count = 0
        text = rp.regex.replace(text) { count++; rp.replacement }
        if (count > 0) {
            actions.add(EnforcementAction.Redact(target = rp.name))
        }
    }
    return RedactionResult(text, actions, emptyList())
}

fun runResponseDataClassification(
    bodyText: String,
    config: PolicyDataClassification?,
    onError: (String) -> Unit
): DataClassificationResult? =
    config?.let { checkDataClassification(bodyText, it, onError) }
