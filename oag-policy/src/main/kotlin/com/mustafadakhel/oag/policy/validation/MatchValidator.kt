package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.DetectedProtocol
import com.mustafadakhel.oag.policy.core.GraphQlOperationType
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyHeaderMatch
import com.mustafadakhel.oag.policy.core.PolicyPayloadMatch
import com.mustafadakhel.oag.policy.core.PolicyQueryMatch

import java.util.Locale

private const val MAX_CONTAINS_TOTAL_LENGTH = 1_000_000

private val VALID_PAYLOAD_PROTOCOLS = DetectedProtocol.validProtocolIds
private val VALID_GRAPHQL_OPERATION_TYPES = GraphQlOperationType.entries.map { it.label() }.toSet()

internal fun PolicyBodyMatch.validate(base: String): List<ValidationError> = buildList {
    if (contains.isNullOrEmpty() && patterns.isNullOrEmpty()) {
        add(ValidationError(base, "Must specify contains or patterns"))
    }
    contains?.let { list ->
        val totalLength = list.sumOf { it.length.toLong() }
        if (totalLength > MAX_CONTAINS_TOTAL_LENGTH) {
            add(ValidationError("$base.contains", "Total pattern length exceeds $MAX_CONTAINS_TOTAL_LENGTH bytes"))
        }
    }
    contains?.forEachIndexed { index, value ->
        if (value.isEmpty()) {
            add(ValidationError("$base.contains[$index]", "Must not be empty"))
        }
    }
    patterns?.forEachIndexed { index, value ->
        addAll(validateRegexField("$base.patterns[$index]", value))
    }
}

internal fun PolicyHeaderMatch.validate(base: String): List<ValidationError> = buildList {
    if (header.isBlank()) {
        add(ValidationError("$base.header", ValidationMessage.MUST_NOT_BE_BLANK))
    } else if (header.any(Char::isWhitespace)) {
        add(ValidationError("$base.header", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
    }
    addAll(validateValuePatternPresent(base, value, pattern, present))
}

internal fun PolicyQueryMatch.validate(base: String): List<ValidationError> = buildList {
    if (param.isBlank()) {
        add(ValidationError("$base.param", ValidationMessage.MUST_NOT_BE_BLANK))
    } else if (param.any(Char::isWhitespace)) {
        add(ValidationError("$base.param", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
    }
    addAll(validateValuePatternPresent(base, value, pattern, present))
}

// present?.let { "" } converts a non-null Boolean to a non-null String sentinel so that
// listOfNotNull counts it alongside the nullable String fields (value, pattern). This
// lets us detect exactly-one-of-three using a single size check.
private fun validateValuePatternPresent(
    base: String,
    value: String?,
    pattern: String?,
    present: Boolean?
): List<ValidationError> = buildList {
    val specCount = listOfNotNull(value, pattern, present?.let { "" }).size
    if (specCount == 0) {
        add(ValidationError(base, "Must specify value, pattern, or present"))
    }
    if (specCount > 1) {
        add(ValidationError(base, "Must specify only one of value, pattern, or present"))
    }
    if (pattern != null) {
        addAll(validateRegexField("$base.pattern", pattern))
    }
}

internal fun PolicyPayloadMatch.validate(base: String): List<ValidationError> = buildList {
    if (protocol.isBlank()) {
        add(ValidationError("$base.protocol", ValidationMessage.MUST_NOT_BE_BLANK))
    } else if (protocol.lowercase(Locale.ROOT) !in VALID_PAYLOAD_PROTOCOLS) {
        add(ValidationError("$base.protocol", "Unknown protocol '${protocol}', must be ${VALID_PAYLOAD_PROTOCOLS.sorted().joinToString(" or ")}"))
    }
    if (method != null && method.isNotEmpty()) {
        runCatching { Regex(method) }.onFailure {
            add(ValidationError("$base.method", "Invalid regex: ${it.message}"))
        }
    }
    if (operation != null && operation.isNotEmpty()) {
        runCatching { Regex(operation) }.onFailure {
            add(ValidationError("$base.operation", "Invalid regex: ${it.message}"))
        }
    }
    if (operationType != null && operationType.lowercase(Locale.ROOT) !in VALID_GRAPHQL_OPERATION_TYPES) {
        add(ValidationError("$base.operation_type", "Unknown operation type '${operationType}'"))
    }
}
