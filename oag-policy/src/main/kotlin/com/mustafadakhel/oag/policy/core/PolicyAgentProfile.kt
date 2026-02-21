package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyAgentProfile(
    val id: String,
    @SerialName("allowed_rules") val allowedRules: List<String>? = null,
    @SerialName("denied_rules") val deniedRules: List<String>? = null,
    @SerialName("max_requests_per_minute") val maxRequestsPerMinute: Int? = null,
    val tags: List<String>? = null,
    @SerialName("max_body_bytes") val maxBodyBytes: Long? = null
)
