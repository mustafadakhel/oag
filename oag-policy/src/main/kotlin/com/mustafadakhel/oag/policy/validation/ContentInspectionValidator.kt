package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.InjectionCategory
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyInjectionScoring
import com.mustafadakhel.oag.policy.core.PolicyMlClassifier
import com.mustafadakhel.oag.policy.core.PolicyUrlInspection
import com.mustafadakhel.oag.policy.core.SensitiveDataCategory

import java.util.Locale

internal fun PolicyContentInspection.validate(base: String): List<ValidationError> = buildList {
    customPatterns?.forEachIndexed { index, value ->
        addAll(validateRegexField("$base.custom_patterns[$index]", value))
    }
    anchoredPatterns?.forEachIndexed { index, ap ->
        addAll(validateRegexField("$base.anchored_patterns[$index].pattern", ap.pattern))
    }
}

private val VALID_SCORING_CATEGORIES = InjectionCategory.entries.map { it.label() }.toSet()

internal fun PolicyInjectionScoring.validate(base: String): List<ValidationError> = buildList {
    if (denyThreshold != null && denyThreshold <= 0.0) {
        add(ValidationError("$base.deny_threshold", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (denyThreshold != null && denyThreshold >= 1.0) {
        add(ValidationError("$base.deny_threshold", "Scores are normalized to [0, 1); threshold >= 1.0 will never trigger"))
    }
    if (logThreshold != null && logThreshold <= 0.0) {
        add(ValidationError("$base.log_threshold", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (logThreshold != null && logThreshold >= 1.0) {
        add(ValidationError("$base.log_threshold", "Scores are normalized to [0, 1); threshold >= 1.0 will never trigger"))
    }
    if (denyThreshold != null && logThreshold != null && logThreshold > denyThreshold) {
        add(ValidationError("$base.log_threshold", "Must not exceed deny_threshold"))
    }
    if (entropyWeight != null && entropyWeight < 0.0) {
        add(ValidationError("$base.entropy_weight", "Must not be negative"))
    }
    if (entropyBaseline != null && entropyBaseline <= 0.0) {
        add(ValidationError("$base.entropy_baseline", ValidationMessage.MUST_BE_POSITIVE))
    }
    categoryWeights?.forEachIndexed { index, cw ->
        if (cw.category.isBlank()) {
            add(ValidationError("$base.category_weights[$index].category", "Must not be empty"))
        } else if (cw.category !in VALID_SCORING_CATEGORIES) {
            add(ValidationError("$base.category_weights[$index].category", "Unknown category '${cw.category}'"))
        }
        if (cw.weight < 0.0) {
            add(ValidationError("$base.category_weights[$index].weight", "Must not be negative"))
        }
    }
}

internal fun PolicyMlClassifier.validate(base: String): List<ValidationError> = buildList {
    if (enabled == true) {
        if (modelPath.isNullOrBlank()) {
            add(ValidationError("$base.model_path", "Must be set when ml_classifier is enabled"))
        }
        // tokenizer_path is reserved for future use; not validated as required
    }
    if (confidenceThreshold != null) {
        if (confidenceThreshold <= 0.0 || confidenceThreshold > 1.0) {
            add(ValidationError("$base.confidence_threshold", "Must be between 0 (exclusive) and 1 (inclusive)"))
        }
    }
    if (maxLength != null && maxLength <= 0) {
        add(ValidationError("$base.max_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (triggerMode != null && triggerMode !in VALID_TRIGGER_MODES) {
        add(ValidationError("$base.trigger_mode", "Must be one of: ${VALID_TRIGGER_MODES.joinToString()}"))
    }
    if (uncertainLow != null && (uncertainLow < 0.0 || uncertainLow >= 1.0)) {
        add(ValidationError("$base.uncertain_low", "Must be in [0.0, 1.0)"))
    }
    if (uncertainHigh != null && (uncertainHigh <= 0.0 || uncertainHigh > 1.0)) {
        add(ValidationError("$base.uncertain_high", "Must be in (0.0, 1.0]"))
    }
}

private val VALID_TRIGGER_MODES = setOf("always", "uncertain_only")

internal fun PolicyUrlInspection.validate(base: String): List<ValidationError> = buildList {
    if (maxQueryLength != null && maxQueryLength <= 0) {
        add(ValidationError("$base.max_query_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (entropyThreshold != null && entropyThreshold <= 0.0) {
        add(ValidationError("$base.entropy_threshold", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (minValueLength != null && minValueLength <= 0) {
        add(ValidationError("$base.min_value_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (maxUrlLength != null && maxUrlLength <= 0) {
        add(ValidationError("$base.max_url_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (maxPathLength != null && maxPathLength <= 0) {
        add(ValidationError("$base.max_path_length", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (pathEntropyThreshold != null && pathEntropyThreshold <= 0.0) {
        add(ValidationError("$base.path_entropy_threshold", ValidationMessage.MUST_BE_POSITIVE))
    }
}

private val VALID_DATA_CLASSIFICATION_CATEGORIES = SensitiveDataCategory.validLabels

internal fun PolicyDataClassification.validate(base: String): List<ValidationError> = buildList {
    customPatterns?.forEachIndexed { index, value ->
        addAll(validateRegexField("$base.custom_patterns[$index]", value))
    }
    categories?.forEachIndexed { index, cat ->
        if (cat.isBlank()) {
            add(ValidationError("$base.categories[$index]", ValidationMessage.MUST_NOT_BE_BLANK))
        } else if (cat.lowercase(Locale.ROOT) !in VALID_DATA_CLASSIFICATION_CATEGORIES) {
            add(ValidationError("$base.categories[$index]", "Unknown category '${cat}'"))
        }
    }
}

internal fun validateRegexField(path: String, pattern: String): List<ValidationError> {
    if (pattern.isEmpty()) return listOf(ValidationError(path, "Must not be empty"))
    return runCatching { Regex(pattern) }.fold(
        onSuccess = { emptyList() },
        onFailure = { listOf(ValidationError(path, "Invalid regex: ${it.message}")) }
    )
}
