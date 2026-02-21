package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesBody
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validate

internal object BodyDimension : MatchDimension {
    override val name = "body_match"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesBody(rule.bodyMatch, request.body, onRegexError)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> =
        rule.bodyMatch?.validate("$base.body_match").orEmpty()

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(
            bodyMatch = rule.bodyMatch?.let {
                it.copy(contains = it.contains?.sorted(), patterns = it.patterns?.sorted())
            }
        )

    override fun normalize(rule: PolicyRule): PolicyRule = rule
}
