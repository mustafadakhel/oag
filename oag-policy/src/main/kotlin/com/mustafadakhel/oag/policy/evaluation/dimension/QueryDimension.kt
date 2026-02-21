package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyQueryMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesQueryParams
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validate

import java.util.Locale

internal object QueryDimension : MatchDimension {
    override val name = "query_match"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesQueryParams(rule.queryMatch, request.path, onRegexError)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> = buildList {
        rule.queryMatch?.forEachIndexed { index, match ->
            addAll(match.validate("$base.query_match[$index]"))
        }
    }

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(
            queryMatch = rule.queryMatch?.sortedWith(
                compareBy<PolicyQueryMatch> { it.param.lowercase(Locale.ROOT) }
                    .thenBy { it.value.orEmpty() }
                    .thenBy { it.pattern.orEmpty() }
                    .thenBy { it.present?.toString().orEmpty() }
            )
        )

    override fun normalize(rule: PolicyRule): PolicyRule = rule
}
