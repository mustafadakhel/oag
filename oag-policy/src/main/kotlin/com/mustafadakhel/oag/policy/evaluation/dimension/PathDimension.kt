package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesPath
import com.mustafadakhel.oag.policy.evaluation.normalizePaths
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validatePaths

internal object PathDimension : MatchDimension {
    override val name = "paths"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesPath(rule.paths, request.path)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> =
        rule.paths.validatePaths("$base.paths")

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(paths = rule.paths?.sorted())

    override fun normalize(rule: PolicyRule): PolicyRule =
        rule.copy(paths = normalizePaths(rule.paths))
}
