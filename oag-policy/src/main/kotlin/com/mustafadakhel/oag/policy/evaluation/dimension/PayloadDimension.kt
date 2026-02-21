package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyPayloadMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesPayload
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validate

internal object PayloadDimension : MatchDimension {
    override val name = "payload_match"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesPayload(rule.payloadMatch, request.structuredPayload, onRegexError)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> = buildList {
        rule.payloadMatch?.forEachIndexed { index, match ->
            addAll(match.validate("$base.payload_match[$index]"))
        }
    }

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(
            payloadMatch = rule.payloadMatch?.sortedWith(
                compareBy<PolicyPayloadMatch> { it.protocol }
                    .thenBy { it.method.orEmpty() }
                    .thenBy { it.operation.orEmpty() }
                    .thenBy { it.operationType.orEmpty() }
            )
        )

    override fun normalize(rule: PolicyRule): PolicyRule = rule
}
