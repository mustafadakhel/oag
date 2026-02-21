package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.FORBIDDEN_REWRITE_HEADERS
import com.mustafadakhel.oag.FindingTypeLabels
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction

import java.util.Locale
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument

data class ValidationError(
    val path: String,
    val message: String
)

class PolicyValidationException(
    val errors: List<ValidationError>
) : RuntimeException(buildMessage(errors))

private fun buildMessage(errors: List<ValidationError>): String =
    "Policy validation failed:\n" + errors.joinToString("\n") { "- ${it.path}: ${it.message}" }

// Per-thread cost: ~4× max_body_bytes (buffer + UTF-8 string + normalized + regex state).
// With default maxThreads=32, total worst case = 32 × 4 × this value.
internal const val MAX_BODY_BYTES_UPPER_BOUND = 10L * 1024 * 1024 // 10 MB
fun validatePolicy(policy: PolicyDocument): List<ValidationError> = buildList {
    when (policy.version) {
        null -> add(ValidationError("version", "Missing required field"))
        1 -> Unit
        else -> add(ValidationError("version", "Unsupported version ${policy.version}"))
    }

    policy.includes?.forEachIndexed { index, path ->
        if (path.isBlank()) {
            add(ValidationError("includes[$index]", ValidationMessage.MUST_NOT_BE_BLANK))
        }
    }

    policy.defaults?.validate()?.forEach { add(it) }

    addAll(validateRules(PolicyAction.ALLOW.label(), policy.allow))
    addAll(validateRules(PolicyAction.DENY.label(), policy.deny))
    addAll(validateSecretScopes(policy.secretScopes))
    addAll(validateRuleIds(policy.allow, policy.deny))
    addAll(validateAgentProfiles(policy))
}

private fun PolicyDefaults.validate(): List<ValidationError> = buildList {
    addAll(validateMaxBodyBytes(maxBodyBytes, "defaults"))
    if (maxResponseScanBytes != null && maxResponseScanBytes <= 0) {
        add(ValidationError("defaults.max_response_scan_bytes", ValidationMessage.MUST_BE_POSITIVE))
    }
    urlInspection?.validate("defaults.url_inspection")?.forEach { add(it) }
    contentInspection?.validate("defaults.content_inspection")?.forEach { add(it) }
    if (maxBytesPerHostPerSession != null && maxBytesPerHostPerSession <= 0) {
        add(ValidationError("defaults.max_bytes_per_host_per_session", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (dnsEntropyThreshold != null && dnsEntropyThreshold <= 0.0) {
        add(ValidationError("defaults.dns_entropy_threshold", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (dnsMinLabelLength != null && dnsMinLabelLength <= 0) {
        add(ValidationError("defaults.dns_min_label_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (maxTokensPerSession != null && maxTokensPerSession <= 0) {
        add(ValidationError("defaults.max_tokens_per_session", ValidationMessage.MUST_BE_POSITIVE))
    }
    injectionScoring?.validate("defaults.injection_scoring")?.forEach { add(it) }
    mlClassifier?.validate("defaults.ml_classifier")?.forEach { add(it) }
    dataClassification?.validate("defaults.data_classification")?.forEach { add(it) }
    if (pluginDetection?.detectorIds?.isEmpty() == true) {
        add(ValidationError("defaults.plugin_detection.detector_ids", "Empty detector_ids list silently disables all detection; omit the field instead"))
    }
    findingSuppressions?.forEachIndexed { index, suppression ->
        if (suppression.detectorId == null && suppression.findingType == null && suppression.pattern == null) {
            add(ValidationError("defaults.finding_suppressions[$index]", "At least one of detector_id, finding_type, or pattern must be set"))
        }
        suppression.findingType?.let { ft ->
            if (ft.trim().lowercase(Locale.ROOT) !in FindingTypeLabels.valid) {
                add(ValidationError("defaults.finding_suppressions[$index].finding_type", "Unknown finding type '$ft'. Valid: ${FindingTypeLabels.valid.sorted().joinToString()}"))
            }
        }
    }
}

internal fun validateMaxBodyBytes(value: Long?, base: String): List<ValidationError> = buildList {
    if (value != null && value <= 0) {
        add(ValidationError("$base.max_body_bytes", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (value != null && value > MAX_BODY_BYTES_UPPER_BOUND) {
        add(ValidationError("$base.max_body_bytes", "Must not exceed $MAX_BODY_BYTES_UPPER_BOUND bytes"))
    }
}
