package com.mustafadakhel.oag

data class RateLimitConfig(
    val ruleId: String,
    val requestsPerSecond: Double,
    val burst: Int
)
