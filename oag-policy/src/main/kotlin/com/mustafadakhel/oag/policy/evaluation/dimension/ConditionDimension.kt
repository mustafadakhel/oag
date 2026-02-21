package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesConditions
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validate

import java.util.Locale

internal object ConditionDimension : MatchDimension {
    override val name = "conditions"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesConditions(rule.conditions, request)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> =
        rule.conditions?.validate("$base.conditions").orEmpty()

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(conditions = rule.conditions?.let { it.copy(ports = it.ports?.sorted()) })

    override fun normalize(rule: PolicyRule): PolicyRule =
        rule.copy(conditions = rule.conditions?.let { it.copy(scheme = it.scheme?.trim()?.lowercase(Locale.ROOT)) })
}
