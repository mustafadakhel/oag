package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesHost
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validateHost

import java.util.Locale

internal object HostDimension : MatchDimension {
    override val name = "host"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesHost(rule.host, request.host)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> = buildList {
        if (rule.host.isNullOrBlank()) {
            add(ValidationError("$base.host", "Missing or empty"))
        } else {
            addAll(validateHost("$base.host", rule.host))
        }
    }

    override fun canonicalize(rule: PolicyRule): PolicyRule = rule

    override fun normalize(rule: PolicyRule): PolicyRule =
        rule.copy(host = rule.host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT))
}
