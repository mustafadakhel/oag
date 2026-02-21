package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyHeaderMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesHeaders
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validate

import java.util.Locale

internal object HeaderDimension : MatchDimension {
    override val name = "header_match"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesHeaders(rule.headerMatch, request.headers, onRegexError)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> = buildList {
        rule.headerMatch?.forEachIndexed { index, match ->
            addAll(match.validate("$base.header_match[$index]"))
        }
    }

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(
            headerMatch = rule.headerMatch?.sortedWith(
                compareBy<PolicyHeaderMatch> { it.header.lowercase(Locale.ROOT) }
                    .thenBy { it.value.orEmpty() }
                    .thenBy { it.pattern.orEmpty() }
                    .thenBy { it.present?.toString().orEmpty() }
            )
        )

    override fun normalize(rule: PolicyRule): PolicyRule = rule
}
