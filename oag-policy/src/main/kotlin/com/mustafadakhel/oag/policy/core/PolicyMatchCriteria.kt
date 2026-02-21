package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyBodyMatch(
    val contains: List<String>? = null,
    val patterns: List<String>? = null
)

@Serializable
data class PolicyQueryMatch(
    val param: String,
    val value: String? = null,
    val pattern: String? = null,
    val present: Boolean? = null
)

@Serializable
data class PolicyHeaderMatch(
    val header: String,
    val value: String? = null,
    val pattern: String? = null,
    val present: Boolean? = null
)

@Serializable
data class PolicyPayloadMatch(
    val protocol: String,
    val method: String? = null,
    val operation: String? = null,
    @SerialName("operation_type") val operationType: String? = null
)
