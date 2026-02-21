package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.policy.core.PolicyDecision

data class RedirectDenial(
    val decision: PolicyDecision,
    val statusCode: Int
)
