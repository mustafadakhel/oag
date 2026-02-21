package com.mustafadakhel.oag

enum class AuthnMethod {
    NONE,
    SIGNATURE,
    CERTIFICATE,
    BEARER_TOKEN
}

data class CertInfo(
    val subject: String,
    val issuer: String? = null,
    val serialNumber: String? = null
)

data class SignatureInfo(
    val agentId: String,
    val verified: Boolean
)
