package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesMethod
import com.mustafadakhel.oag.policy.evaluation.normalizeMethods
import com.mustafadakhel.oag.policy.validation.VALID_METHODS
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validateMethods

internal object MethodDimension : MatchDimension {
    override val name = "methods"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesMethod(rule.methods, request.method)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> =
        rule.methods.validateMethods(VALID_METHODS, "$base.methods")

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(methods = rule.methods?.sorted())

    override fun normalize(rule: PolicyRule): PolicyRule =
        rule.copy(methods = normalizeMethods(rule.methods))
}
