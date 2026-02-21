package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope

enum class DiffChangeType {
    ADDED, REMOVED, CHANGED
}

data class RuleDiff(
    val section: String,
    val id: String?,
    val change: DiffChangeType,
    val details: List<String> = emptyList()
)

data class PolicyDiffResult(
    val defaultsChanged: Boolean,
    val defaultsDetails: List<String>,
    val ruleDiffs: List<RuleDiff>,
    val secretScopeDiffs: List<RuleDiff>
) {
    val hasChanges: Boolean get() = defaultsChanged || ruleDiffs.isNotEmpty() || secretScopeDiffs.isNotEmpty()
}

fun diffPolicies(oldPolicy: PolicyDocument, newPolicy: PolicyDocument): PolicyDiffResult {
    val defaultsDetails = diffDefaults(oldPolicy.defaults, newPolicy.defaults)
    val ruleDiffs = diffRuleList(PolicyAction.ALLOW.label(), oldPolicy.allow.orEmpty(), newPolicy.allow.orEmpty()) +
        diffRuleList(PolicyAction.DENY.label(), oldPolicy.deny.orEmpty(), newPolicy.deny.orEmpty())
    val scopeDiffs = diffSecretScopes(oldPolicy.secretScopes.orEmpty(), newPolicy.secretScopes.orEmpty())

    return PolicyDiffResult(
        defaultsChanged = defaultsDetails.isNotEmpty(),
        defaultsDetails = defaultsDetails,
        ruleDiffs = ruleDiffs,
        secretScopeDiffs = scopeDiffs
    )
}

private inline fun MutableList<String>.diff(label: String, oldVal: Any?, newVal: Any?) {
    if (oldVal != newVal) add("$label: $oldVal -> $newVal")
}

private inline fun MutableList<String>.diffComplex(label: String, oldVal: Any?, newVal: Any?) {
    if (oldVal != newVal) add("$label: changed")
}

private fun diffDefaults(old: PolicyDefaults?, new: PolicyDefaults?): List<String> {
    if (old == new) return emptyList()
    return buildList {
        diff("action", old?.action, new?.action)
        diff("max_body_bytes", old?.maxBodyBytes, new?.maxBodyBytes)
        diff("enforce_dns_resolution", old?.enforceDnsResolution, new?.enforceDnsResolution)
        diff("block_dns_exfiltration", old?.blockDnsExfiltration, new?.blockDnsExfiltration)
        diff("dns_entropy_threshold", old?.dnsEntropyThreshold, new?.dnsEntropyThreshold)
        diff("dns_min_label_length", old?.dnsMinLabelLength, new?.dnsMinLabelLength)
        diff("max_response_scan_bytes", old?.maxResponseScanBytes, new?.maxResponseScanBytes)
        diff("max_bytes_per_host_per_session", old?.maxBytesPerHostPerSession, new?.maxBytesPerHostPerSession)
        diff("scan_streaming_responses", old?.scanStreamingResponses, new?.scanStreamingResponses)
        diffComplex("url_inspection", old?.urlInspection, new?.urlInspection)
        diffComplex("content_inspection", old?.contentInspection, new?.contentInspection)
        diffComplex("injection_scoring", old?.injectionScoring, new?.injectionScoring)
        diffComplex("ml_classifier", old?.mlClassifier, new?.mlClassifier)
        diff("outbound_credential_detection", old?.outboundCredentialDetection, new?.outboundCredentialDetection)
        diff("max_tokens_per_session", old?.maxTokensPerSession, new?.maxTokensPerSession)
        diffComplex("data_classification", old?.dataClassification, new?.dataClassification)
        diffComplex("plugin_detection", old?.pluginDetection, new?.pluginDetection)
        diffComplex("finding_suppressions", old?.findingSuppressions, new?.findingSuppressions)
    }
}

private fun diffRuleList(section: String, oldRules: List<PolicyRule>, newRules: List<PolicyRule>): List<RuleDiff> {
    val oldById = oldRules.groupBy { it.id }.mapValues { it.value.last() }
    val newById = newRules.groupBy { it.id }.mapValues { it.value.last() }

    return buildList {
        for (rule in oldRules) {
            val id = rule.id
            if (id != null && id !in newById) {
                add(RuleDiff(section, id, DiffChangeType.REMOVED))
            } else if (id == null && rule !in newRules) {
                add(RuleDiff(section, null, DiffChangeType.REMOVED, listOf("host=${rule.host}")))
            }
        }

        for (rule in newRules) {
            val id = rule.id
            if (id != null && id !in oldById) {
                add(RuleDiff(section, id, DiffChangeType.ADDED))
            } else if (id == null && rule !in oldRules) {
                add(RuleDiff(section, null, DiffChangeType.ADDED, listOf("host=${rule.host}")))
            }
        }

        for ((id, newRule) in newById) {
            if (id == null) continue
            val oldRule = oldById[id] ?: continue
            if (oldRule != newRule) {
                add(RuleDiff(section, id, DiffChangeType.CHANGED, diffRule(oldRule, newRule)))
            }
        }
    }
}

private fun diffRule(old: PolicyRule, new: PolicyRule): List<String> = buildList {
    diff("host", old.host, new.host)
    diff("methods", old.methods, new.methods)
    diff("paths", old.paths, new.paths)
    diff("secrets", old.secrets, new.secrets)
    diff("ip_ranges", old.ipRanges, new.ipRanges)
    diff("max_body_bytes", old.maxBodyBytes, new.maxBodyBytes)
    diffComplex("conditions", old.conditions, new.conditions)
    diff("reason_code", old.reasonCode, new.reasonCode)
    diffComplex("rate_limit", old.rateLimit, new.rateLimit)
    diffComplex("body_match", old.bodyMatch, new.bodyMatch)
    diffComplex("response_body_match", old.responseBodyMatch, new.responseBodyMatch)
    diffComplex("content_inspection", old.contentInspection, new.contentInspection)
    diff("skip_content_inspection", old.skipContentInspection, new.skipContentInspection)
    diff("skip_response_scanning", old.skipResponseScanning, new.skipResponseScanning)
    diff("tls_inspect", old.tlsInspect, new.tlsInspect)
    diffComplex("header_rewrites", old.headerRewrites, new.headerRewrites)
    diff("connect_timeout_ms", old.connectTimeoutMs, new.connectTimeoutMs)
    diff("read_timeout_ms", old.readTimeoutMs, new.readTimeoutMs)
    diffComplex("retry", old.retry, new.retry)
    diffComplex("header_match", old.headerMatch, new.headerMatch)
    diffComplex("query_match", old.queryMatch, new.queryMatch)
    diff("tags", old.tags, new.tags)
    diffComplex("error_response", old.errorResponse, new.errorResponse)
    diff("skip_outbound_credential_detection", old.skipOutboundCredentialDetection, new.skipOutboundCredentialDetection)
    diffComplex("data_classification", old.dataClassification, new.dataClassification)
    diff("skip_data_classification", old.skipDataClassification, new.skipDataClassification)
    diffComplex("response_rewrites", old.responseRewrites, new.responseRewrites)
    diffComplex("payload_match", old.payloadMatch, new.payloadMatch)
    diffComplex("plugin_detection", old.pluginDetection, new.pluginDetection)
    diff("skip_plugin_detection", old.skipPluginDetection, new.skipPluginDetection)
    diffComplex("finding_suppressions", old.findingSuppressions, new.findingSuppressions)
    diff("webhook_events", old.webhookEvents, new.webhookEvents)
}

private fun diffSecretScopes(oldScopes: List<SecretScope>, newScopes: List<SecretScope>): List<RuleDiff> {
    val oldById = oldScopes.groupBy { it.id }.mapValues { it.value.last() }
    val newById = newScopes.groupBy { it.id }.mapValues { it.value.last() }

    return buildList {
        for (scope in oldScopes) {
            val id = scope.id
            if (id != null && id !in newById) {
                add(RuleDiff("secret_scopes", id, DiffChangeType.REMOVED))
            }
        }

        for (scope in newScopes) {
            val id = scope.id
            if (id != null && id !in oldById) {
                add(RuleDiff("secret_scopes", id, DiffChangeType.ADDED))
            }
        }

        for ((id, newScope) in newById) {
            if (id == null) continue
            val oldScope = oldById[id] ?: continue
            if (oldScope != newScope) {
                val details = buildList {
                    diff("hosts", oldScope.hosts, newScope.hosts)
                    diff("methods", oldScope.methods, newScope.methods)
                    diff("paths", oldScope.paths, newScope.paths)
                    diff("ip_ranges", oldScope.ipRanges, newScope.ipRanges)
                }
                add(RuleDiff("secret_scopes", id, DiffChangeType.CHANGED, details))
            }
        }
    }
}
