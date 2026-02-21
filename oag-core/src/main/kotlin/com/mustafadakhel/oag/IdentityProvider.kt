package com.mustafadakhel.oag

data class IdentityResult(
    val actorId: String? = null,
    val authnMethod: AuthnMethod = AuthnMethod.NONE,
    val certInfo: CertInfo? = null,
    val signatureInfo: SignatureInfo? = null
) {
    init {
        require(certInfo == null || signatureInfo == null) {
            "IdentityResult cannot have both certInfo and signatureInfo"
        }
    }

    val authenticated: Boolean get() = authnMethod != AuthnMethod.NONE
}

fun interface IdentityProvider {
    fun extract(headers: Map<String, String>): IdentityResult
}
