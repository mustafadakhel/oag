package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.ALL_HTTP_METHODS
import com.mustafadakhel.oag.FindingSeverityLabels
import com.mustafadakhel.oag.FindingTypeLabels
import com.mustafadakhel.oag.WebhookEventLabels
import com.mustafadakhel.oag.policy.core.PolicyRule

import java.util.Locale

internal fun validateRules(
    ruleSet: String,
    rules: List<PolicyRule>?
): List<ValidationError> =
    rules.orEmpty().flatMapIndexed { index, rule ->
        rule.validate("$ruleSet[$index]", VALID_METHODS)
    }

internal fun PolicyRule.validate(base: String, validMethods: Set<String>): List<ValidationError> = buildList {
    if (id.isNullOrBlank()) {
        add(ValidationError("$base.id", "Missing or empty"))
    } else if (id.any(Char::isWhitespace)) {
        add(ValidationError("$base.id", "Rule id must not contain whitespace"))
    }
    if (host.isNullOrBlank()) {
        add(ValidationError("$base.host", "Missing or empty"))
    } else {
        validateHost("$base.host", host).forEach { add(it) }
    }

    methods.validateMethods(validMethods, "$base.methods").forEach { add(it) }
    paths.validatePaths("$base.paths").forEach { add(it) }
    secrets.validateSecrets("$base.secrets").forEach { add(it) }
    ipRanges.validateIpRanges("$base.ip_ranges").forEach { add(it) }

    addAll(validateMaxBodyBytes(maxBodyBytes, base))

    conditions?.validate("$base.conditions")?.forEach { add(it) }

    if (reasonCode != null) {
        val trimmed = reasonCode.trim()
        when {
            trimmed.isEmpty() -> add(ValidationError("$base.reason_code", "Must not be empty"))
            trimmed.any(Char::isWhitespace) -> add(ValidationError("$base.reason_code", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
        }
    }

    rateLimit?.validate("$base.rate_limit")?.forEach { add(it) }
    bodyMatch?.validate("$base.body_match")?.forEach { add(it) }
    responseBodyMatch?.validate("$base.response_body_match")?.forEach { add(it) }
    contentInspection?.validate("$base.content_inspection")?.forEach { add(it) }
    if (skipContentInspection == true && contentInspection != null) {
        add(ValidationError("$base.skip_content_inspection", "Cannot set both skip_content_inspection and content_inspection"))
    }
    if (skipPluginDetection == true && pluginDetection != null) {
        add(ValidationError("$base.skip_plugin_detection", "Cannot set both skip_plugin_detection and plugin_detection"))
    }
    if (pluginDetection?.detectorIds?.isEmpty() == true) {
        add(ValidationError("$base.plugin_detection.detector_ids", "Empty detector_ids list silently disables all detection; omit the field or use skip_plugin_detection"))
    }
    pluginDetection?.denySeverityThreshold?.let { threshold ->
        if (threshold.trim().lowercase(Locale.ROOT) !in FindingSeverityLabels.valid) {
            add(ValidationError("$base.plugin_detection.deny_severity_threshold", "Unknown severity '$threshold'. Valid: ${FindingSeverityLabels.valid.joinToString()}"))
        }
    }
    findingSuppressions?.forEachIndexed { index, suppression ->
        if (suppression.detectorId == null && suppression.findingType == null && suppression.pattern == null) {
            add(ValidationError("$base.finding_suppressions[$index]", "At least one of detector_id, finding_type, or pattern must be set"))
        }
        suppression.findingType?.let { ft ->
            if (ft.trim().lowercase(Locale.ROOT) !in FindingTypeLabels.valid) {
                add(ValidationError("$base.finding_suppressions[$index].finding_type", "Unknown finding type '$ft'. Valid: ${FindingTypeLabels.valid.sorted().joinToString()}"))
            }
        }
    }
    headerRewrites?.forEachIndexed { index, rewrite ->
        rewrite.validate("$base.header_rewrites[$index]").forEach { add(it) }
    }
    if (connectTimeoutMs != null && connectTimeoutMs <= 0) {
        add(ValidationError("$base.connect_timeout_ms", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (readTimeoutMs != null && readTimeoutMs <= 0) {
        add(ValidationError("$base.read_timeout_ms", ValidationMessage.MUST_BE_POSITIVE))
    }
    retry?.validate("$base.retry")?.forEach { add(it) }
    headerMatch?.forEachIndexed { index, match ->
        match.validate("$base.header_match[$index]").forEach { add(it) }
    }
    queryMatch?.forEachIndexed { index, match ->
        match.validate("$base.query_match[$index]").forEach { add(it) }
    }
    tags?.forEachIndexed { index, tag ->
        if (tag.isBlank()) {
            add(ValidationError("$base.tags[$index]", ValidationMessage.MUST_NOT_BE_BLANK))
        } else if (tag.any(Char::isWhitespace)) {
            add(ValidationError("$base.tags[$index]", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
        }
    }
    errorResponse?.validate("$base.error_response")?.forEach { add(it) }
    dataClassification?.validate("$base.data_classification")?.forEach { add(it) }
    if (skipDataClassification == true && dataClassification != null) {
        add(ValidationError("$base.skip_data_classification", "Cannot set both skip_data_classification and data_classification"))
    }
    responseRewrites?.forEachIndexed { index, rewrite ->
        rewrite.validate("$base.response_rewrites[$index]").forEach { add(it) }
    }
    payloadMatch?.forEachIndexed { index, match ->
        match.validate("$base.payload_match[$index]").forEach { add(it) }
    }
    webhookEvents?.forEachIndexed { index, event ->
        if (event.trim().lowercase(Locale.ROOT) !in WebhookEventLabels.valid) {
            add(ValidationError("$base.webhook_events[$index]", "Unknown webhook event type '$event'. Valid: ${WebhookEventLabels.valid.joinToString()}"))
        }
    }
}

internal fun validateRuleIds(
    allow: List<PolicyRule>?,
    deny: List<PolicyRule>?
): List<ValidationError> {
    val allowEntries = allow.orEmpty().mapIndexedNotNull { index, rule ->
        rule.id?.trim()?.takeIf { it.isNotEmpty() }?.let { it to "allow[$index].id" }
    }
    val denyEntries = deny.orEmpty().mapIndexedNotNull { index, rule ->
        rule.id?.trim()?.takeIf { it.isNotEmpty() }?.let { it to "deny[$index].id" }
    }
    val occurrences = (allowEntries + denyEntries).groupBy({ it.first }, { it.second })

    return occurrences.filterValues { it.size > 1 }.flatMap { (id, paths) ->
        paths.map { path ->
            ValidationError(path, "Duplicate rule id '$id' also used at ${paths.filter { it != path }.joinToString()}")
        }
    }
}

internal val VALID_METHODS = ALL_HTTP_METHODS

