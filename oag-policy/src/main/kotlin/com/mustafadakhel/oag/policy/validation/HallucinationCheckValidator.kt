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

import com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck
import com.mustafadakhel.oag.policy.core.PolicyHallucinationWeights

internal fun PolicyHallucinationCheck.validate(base: String): List<ValidationError> = buildList {
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

    if (externalEndpointUrl != null) {
        val trimmed = externalEndpointUrl.trim()
        if (trimmed.isBlank()) {
            add(ValidationError("$base.external_endpoint_url", ValidationMessage.MUST_NOT_BE_BLANK))
        } else {
            runCatching { java.net.URI(trimmed) }.fold(
                onSuccess = { uri ->
                    if (uri.scheme !in ALLOWED_ENDPOINT_SCHEMES) {
                        add(ValidationError("$base.external_endpoint_url", "Scheme must be http or https"))
                    }
                },
                onFailure = {
                    add(ValidationError("$base.external_endpoint_url", "Invalid URL: ${it.message}"))
                }
            )
        }
    }

    if (externalEndpointTimeoutMs != null && externalEndpointTimeoutMs <= 0) {
        add(ValidationError("$base.external_endpoint_timeout_ms", ValidationMessage.MUST_BE_POSITIVE))
    }

    signalWeights?.validate("$base.signal_weights")?.forEach { add(it) }

    urlVerificationAllowlist?.forEachIndexed { index, entry ->
        if (entry.isBlank()) {
            add(ValidationError("$base.url_verification_allowlist[$index]", ValidationMessage.MUST_NOT_BE_BLANK))
        }
    }

    if (packageRegistryMirror != null && packageRegistryMirror.isBlank()) {
        add(ValidationError("$base.package_registry_mirror", ValidationMessage.MUST_NOT_BE_BLANK))
    }
}

internal fun PolicyHallucinationWeights.validate(base: String): List<ValidationError> = buildList {
    if (impossibleClaims != null && impossibleClaims < 0.0) {
        add(ValidationError("$base.impossible_claims", "Must not be negative"))
    }
    if (urlVerification != null && urlVerification < 0.0) {
        add(ValidationError("$base.url_verification", "Must not be negative"))
    }
    if (packageVerification != null && packageVerification < 0.0) {
        add(ValidationError("$base.package_verification", "Must not be negative"))
    }
    if (logprobAnalysis != null && logprobAnalysis < 0.0) {
        add(ValidationError("$base.logprob_analysis", "Must not be negative"))
    }
    if (claimContradiction != null && claimContradiction < 0.0) {
        add(ValidationError("$base.claim_contradiction", "Must not be negative"))
    }
    if (toolReceiptVerification != null && toolReceiptVerification < 0.0) {
        add(ValidationError("$base.tool_receipt_verification", "Must not be negative"))
    }
    if (externalNli != null && externalNli < 0.0) {
        add(ValidationError("$base.external_nli", "Must not be negative"))
    }
}

private val ALLOWED_ENDPOINT_SCHEMES = setOf("http", "https")
