package com.mustafadakhel.oag.pipeline

data class SecurityConfig(
    val agentSigningSecret: String?,
    val requireSignedHeaders: Boolean
)
