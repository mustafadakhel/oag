/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyTopicClassification

private const val MAX_TOPIC_LABEL_LENGTH = 256
private const val MAX_ENDPOINT_TIMEOUT_MS = 10_000
private val VALID_ON_ERROR = setOf("deny", "allow")
private val ALLOWED_ENDPOINT_SCHEMES = setOf("http", "https")

internal fun PolicyTopicClassification.validate(base: String): List<ValidationError> = buildList {
    if (enabled == true && endpointUrl == null) {
        add(ValidationError("$base.endpoint_url", "Must be set when topic_classification is enabled"))
    }

    if (endpointUrl != null) {
        val trimmed = endpointUrl.trim()
        if (trimmed.isBlank()) {
            add(ValidationError("$base.endpoint_url", ValidationMessage.MUST_NOT_BE_BLANK))
        } else {
            runCatching { java.net.URI(trimmed) }.fold(
                onSuccess = { uri ->
                    if (uri.scheme !in ALLOWED_ENDPOINT_SCHEMES) {
                        add(ValidationError("$base.endpoint_url", "Scheme must be http or https"))
                    }
                    if (uri.host.isNullOrBlank()) {
                        add(ValidationError("$base.endpoint_url", "URL must have a host"))
                    }
                    if (uri.userInfo != null) {
                        add(ValidationError("$base.endpoint_url", "URL must not contain userinfo"))
                    }
                    if (uri.scheme == "http") {
                        add(ValidationError("$base.endpoint_url", "http scheme is insecure; use https"))
                    }
                },
                onFailure = {
                    add(ValidationError("$base.endpoint_url", "Invalid URL: ${it.message}"))
                }
            )
        }
    }

    if (deniedTopics != null && allowedTopics != null) {
        add(ValidationError("$base", "Cannot set both denied_topics and allowed_topics"))
    }

    if (enabled == true && deniedTopics.isNullOrEmpty() && allowedTopics.isNullOrEmpty()) {
        add(ValidationError("$base", "At least one of denied_topics or allowed_topics must be non-empty when enabled"))
    }

    deniedTopics?.forEachIndexed { index, label ->
        validateTopicLabel("$base.denied_topics[$index]", label).forEach { add(it) }
    }

    allowedTopics?.forEachIndexed { index, label ->
        validateTopicLabel("$base.allowed_topics[$index]", label).forEach { add(it) }
    }

    if (confidenceThreshold != null && (confidenceThreshold <= 0.0 || confidenceThreshold > 1.0)) {
        add(ValidationError("$base.confidence_threshold", "Must be between 0 (exclusive) and 1 (inclusive)"))
    }

    if (endpointTimeoutMs != null) {
        if (endpointTimeoutMs <= 0) {
            add(ValidationError("$base.endpoint_timeout_ms", ValidationMessage.MUST_BE_POSITIVE))
        } else if (endpointTimeoutMs > MAX_ENDPOINT_TIMEOUT_MS) {
            add(ValidationError("$base.endpoint_timeout_ms", "Must not exceed $MAX_ENDPOINT_TIMEOUT_MS"))
        }
    }

    if (maxTextBytes != null && maxTextBytes <= 0) {
        add(ValidationError("$base.max_text_bytes", ValidationMessage.MUST_BE_POSITIVE))
    }

    if (onError != null && onError !in VALID_ON_ERROR) {
        add(ValidationError("$base.on_error", "Must be one of: ${VALID_ON_ERROR.joinToString()}"))
    }
}

private fun validateTopicLabel(path: String, label: String): List<ValidationError> = buildList {
    if (label.isBlank()) {
        add(ValidationError(path, ValidationMessage.MUST_NOT_BE_BLANK))
        return@buildList
    }
    if (label.any { it.isISOControl() }) {
        add(ValidationError(path, "Must not contain control characters"))
    }
    if (label.length > MAX_TOPIC_LABEL_LENGTH) {
        add(ValidationError(path, "Must not exceed $MAX_TOPIC_LABEL_LENGTH characters"))
    }
}
