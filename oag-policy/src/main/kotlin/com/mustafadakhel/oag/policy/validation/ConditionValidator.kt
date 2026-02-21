package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.SCHEME_HTTP
import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.VALID_PORT_RANGE
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyErrorResponse
import com.mustafadakhel.oag.policy.core.PolicyRateLimit
import com.mustafadakhel.oag.policy.core.PolicyRetry

import java.util.Locale

private val VALID_SCHEMES = setOf(SCHEME_HTTP, SCHEME_HTTPS)

private const val MAX_ERROR_RESPONSE_BODY_LENGTH = 8192

internal fun PolicyCondition.validate(base: String): List<ValidationError> = buildList {
    if (scheme != null) {
        val normalized = scheme.trim().lowercase(Locale.ROOT)
        if (normalized !in VALID_SCHEMES) {
            add(ValidationError("$base.scheme", "Unsupported scheme '$scheme', must be http or https"))
        }
    }
    ports?.let { portList ->
        val seen = mutableSetOf<Int>()
        portList.forEachIndexed { index, port ->
            if (port !in VALID_PORT_RANGE) add(ValidationError("$base.ports[$index]", "Port must be between 1 and 65535"))
            if (!seen.add(port)) add(ValidationError("$base.ports[$index]", "Duplicate port $port"))
        }
    }
}

internal fun PolicyRateLimit.validate(base: String): List<ValidationError> = buildList {
    if (requestsPerSecond != null && requestsPerSecond <= 0.0) {
        add(ValidationError("$base.requests_per_second", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (burst != null && burst <= 0) {
        add(ValidationError("$base.burst", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (requestsPerSecond == null || burst == null) {
        add(ValidationError(base, "Must specify both requests_per_second and burst"))
    }
}

internal fun PolicyRetry.validate(base: String): List<ValidationError> = buildList {
    if (maxRetries != null && maxRetries <= 0) {
        add(ValidationError("$base.max_retries", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (retryDelayMs != null && retryDelayMs <= 0) {
        add(ValidationError("$base.retry_delay_ms", ValidationMessage.MUST_BE_POSITIVE))
    }
    if (maxRetries == null && retryDelayMs == null) {
        add(ValidationError(base, "Must specify max_retries or retry_delay_ms"))
    }
}

internal fun PolicyErrorResponse.validate(base: String): List<ValidationError> = buildList {
    if (status != null && (status < 400 || status > 599)) {
        add(ValidationError("$base.status", "Must be between 400 and 599"))
    }
    if (body != null && body.length > MAX_ERROR_RESPONSE_BODY_LENGTH) {
        add(ValidationError("$base.body", "Must not exceed $MAX_ERROR_RESPONSE_BODY_LENGTH characters"))
    }
}
