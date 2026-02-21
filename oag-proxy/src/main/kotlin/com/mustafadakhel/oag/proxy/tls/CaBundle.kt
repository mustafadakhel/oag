package com.mustafadakhel.oag.proxy.tls

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.MS_PER_DAY

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date

private const val CA_KEY_SIZE = 4096
private const val CA_VALIDITY_DAYS = 365L
private val CA_SIGNATURE_ALGORITHM = CryptoConstants.SHA256_WITH_RSA
internal const val CA_SUBJECT_DN = "CN=OAG MITM CA,O=OAG,OU=Proxy"

data class CaBundle(
    val certificate: X509Certificate,
    val keyPair: KeyPair
)

internal fun generateCaBundle(
    subjectDn: String = CA_SUBJECT_DN,
    keySizeBits: Int = CA_KEY_SIZE,
    validityDays: Long = CA_VALIDITY_DAYS
): CaBundle {
    installBouncyCastleProvider()
    require(keySizeBits >= 2048) { "CA key size must be at least 2048 bits" }
    require(validityDays > 0) { "Validity days must be positive" }

    val keyPair = KeyPairGenerator.getInstance(CryptoConstants.RSA).run {
        initialize(keySizeBits, SecureRandom())
        generateKeyPair()
    }

    val now = Date()
    val notAfter = Date(now.time + validityDays * MS_PER_DAY)
    val serial = BigInteger(128, SecureRandom())
    val issuer = X500Name(subjectDn)

    val builder = JcaX509v3CertificateBuilder(
        issuer, serial, now, notAfter, issuer, keyPair.public
    ).apply {
        addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
    }

    val signer = JcaContentSignerBuilder(CA_SIGNATURE_ALGORITHM)
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(keyPair.private)

    val certificate = JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(builder.build(signer))

    return CaBundle(certificate = certificate, keyPair = keyPair)
}

private val bouncyCastleInstalled: Unit by lazy {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(BouncyCastleProvider())
    }
}

internal fun installBouncyCastleProvider() {
    bouncyCastleInstalled
}
