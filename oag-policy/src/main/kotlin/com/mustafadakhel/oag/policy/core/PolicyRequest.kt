package com.mustafadakhel.oag.policy.core

data class PolicyRequest(
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val path: String,
    val body: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val structuredPayload: StructuredPayload? = null
)
