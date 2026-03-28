package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyTopicClassification(
    val enabled: Boolean? = null,
    @SerialName("denied_topics") val deniedTopics: List<String>? = null,
    @SerialName("allowed_topics") val allowedTopics: List<String>? = null,
    @SerialName("confidence_threshold") val confidenceThreshold: Double? = null,
    @SerialName("endpoint_url") val endpointUrl: String? = null,
    @SerialName("endpoint_timeout_ms") val endpointTimeoutMs: Int? = null,
    @SerialName("signing_secret") val signingSecret: String? = null,
    @SerialName("on_error") val onError: String? = null,
    @SerialName("max_text_bytes") val maxTextBytes: Int? = null
)
