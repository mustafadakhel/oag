package com.mustafadakhel.oag.policy.core

data class PolicyMatch(
    val decision: PolicyDecision,
    val rule: PolicyRule?
)
