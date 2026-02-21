package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyAgentProfile
import com.mustafadakhel.oag.policy.evaluation.dimension.matchDimensions
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyMatch
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode

fun evaluatePolicy(
    policy: PolicyDocument,
    request: PolicyRequest,
    onRegexError: (String) -> Unit = {}
): PolicyDecision =
    evaluatePolicyWithRule(policy, request, onRegexError = onRegexError).decision

fun evaluatePolicyWithRule(
    policy: PolicyDocument,
    request: PolicyRequest,
    agentProfile: PolicyAgentProfile? = null,
    onRegexError: (String) -> Unit = {}
): PolicyMatch {
    val denyRules = filterRulesByProfile(policy.deny, agentProfile)
    val allowRules = filterRulesByProfile(policy.allow, agentProfile)

    denyRules?.firstOrNull { ruleMatches(it, request, onRegexError) }?.let { denyMatch ->
        return PolicyMatch(
            decision = PolicyDecision(
                action = PolicyAction.DENY,
                ruleId = denyMatch.id,
                reasonCode = ReasonCode.DENIED_BY_RULE,
                customReasonCode = denyMatch.reasonCode
            ),
            rule = denyMatch
        )
    }

    allowRules?.firstOrNull { ruleMatches(it, request, onRegexError) }?.let { allowMatch ->
        return PolicyMatch(
            decision = PolicyDecision(
                action = PolicyAction.ALLOW,
                ruleId = allowMatch.id,
                reasonCode = ReasonCode.ALLOWED_BY_RULE,
                customReasonCode = allowMatch.reasonCode
            ),
            rule = allowMatch
        )
    }

    val defaultAction = policy.defaults?.action ?: PolicyAction.DENY
    return if (defaultAction == PolicyAction.ALLOW) {
        PolicyMatch(PolicyDecision(action = PolicyAction.ALLOW, ruleId = null, reasonCode = ReasonCode.NO_MATCH_DEFAULT_ALLOW), null)
    } else {
        PolicyMatch(PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.NO_MATCH_DEFAULT_DENY), null)
    }
}

private fun filterRulesByProfile(
    rules: List<PolicyRule>?,
    profile: PolicyAgentProfile?
): List<PolicyRule>? {
    if (profile == null || rules == null) return rules
    return when {
        profile.allowedRules != null -> {
            val allowed = profile.allowedRules.toSet()
            rules.filter { it.id in allowed }
        }
        profile.deniedRules != null -> {
            val denied = profile.deniedRules.toSet()
            rules.filter { it.id != null && it.id !in denied }
        }
        else -> rules
    }
}

private fun ruleMatches(rule: PolicyRule, request: PolicyRequest, onRegexError: (String) -> Unit = {}): Boolean =
    matchDimensions.all { it.matches(rule, request, onRegexError) }


