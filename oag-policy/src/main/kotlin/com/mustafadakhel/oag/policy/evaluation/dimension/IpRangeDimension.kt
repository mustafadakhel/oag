package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.evaluation.matchesIpRange
import com.mustafadakhel.oag.policy.evaluation.normalizeIpRanges
import com.mustafadakhel.oag.policy.validation.ValidationError
import com.mustafadakhel.oag.policy.validation.validateIpRanges

internal object IpRangeDimension : MatchDimension {
    override val name = "ip_ranges"

    override fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit): Boolean =
        matchesIpRange(rule.ipRanges, request.host)

    override fun validate(rule: PolicyRule, base: String): List<ValidationError> =
        rule.ipRanges.validateIpRanges("$base.ip_ranges")

    override fun canonicalize(rule: PolicyRule): PolicyRule =
        rule.copy(ipRanges = rule.ipRanges?.sorted())

    override fun normalize(rule: PolicyRule): PolicyRule =
        rule.copy(ipRanges = normalizeIpRanges(rule.ipRanges))
}
