package com.mustafadakhel.oag.policy.evaluation.dimension

import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.validation.ValidationError

interface MatchDimension {
    val name: String
    fun matches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit = {}): Boolean
    fun validate(rule: PolicyRule, base: String): List<ValidationError>
    fun canonicalize(rule: PolicyRule): PolicyRule
    fun normalize(rule: PolicyRule): PolicyRule
}

internal val matchDimensions: List<MatchDimension> = listOf(
    HostDimension,
    MethodDimension,
    PathDimension,
    IpRangeDimension,
    ConditionDimension,
    BodyDimension,
    HeaderDimension,
    QueryDimension,
    PayloadDimension
)
