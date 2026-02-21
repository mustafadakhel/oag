package com.mustafadakhel.oag

object CryptoConstants {
    const val SHA_256 = "SHA-256"
    const val HMAC_SHA_256 = "HmacSHA256"
    const val RSA = "RSA"
    const val SHA256_WITH_RSA = "SHA256WithRSAEncryption"
    const val ED25519 = "ed25519"
    const val PEM_BEGIN_PREFIX = "-----BEGIN"
    const val PEM_END_PREFIX = "-----END"
    const val PEM_BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
    const val PEM_END_CERTIFICATE = "-----END CERTIFICATE-----"
    const val KEYSTORE_PKCS12 = "PKCS12"
    const val CERT_X509 = "X.509"
    const val TLS = "TLS"
    const val SIGNATURE_PREFIX_HMAC_SHA256 = "hmac-sha256="
    const val SIGNATURE_PREFIX_SHA256 = "sha256="
}
