package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicySchemaValidation
import com.mustafadakhel.oag.validateJsonPointer

private val VALID_ON_FAIL = setOf("block", "pass")

internal fun PolicySchemaValidation.validate(base: String): List<ValidationError> = buildList {
    if (schema.isNullOrBlank()) {
        add(ValidationError("$base.schema", "Must be set"))
    }

    if (onFail != null && onFail.lowercase() !in VALID_ON_FAIL) {
        add(ValidationError("$base.on_fail", "Must be one of: ${VALID_ON_FAIL.joinToString()}"))
    }

    if (extractPath != null) {
        val error = validateJsonPointer(extractPath)
        if (error != null) {
            add(ValidationError("$base.extract_path", error))
        }
    }
}
