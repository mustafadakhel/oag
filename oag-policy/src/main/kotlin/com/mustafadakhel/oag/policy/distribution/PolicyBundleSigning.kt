package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.CryptoConstants

import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

private val WHITESPACE_REGEX = Regex("\\s")

fun signPolicyHash(policyHash: String, privateKey: PrivateKey): String {
    val signature = Signature.getInstance(CryptoConstants.ED25519)
    signature.initSign(privateKey)
    signature.update(policyHash.toByteArray(Charsets.UTF_8))
    val raw = signature.sign()
    return Base64.getEncoder().encodeToString(raw)
}

fun verifyPolicyHash(policyHash: String, signatureBase64: String, publicKey: PublicKey): Boolean {
    val signature = Signature.getInstance(CryptoConstants.ED25519)
    signature.initVerify(publicKey)
    signature.update(policyHash.toByteArray(Charsets.UTF_8))
    val rawSignature = Base64.getDecoder().decode(signatureBase64)
    return signature.verify(rawSignature)
}

fun loadEd25519PrivateKey(path: Path): PrivateKey {
    val keyBytes = readKeyBytes(path)
    val keySpec = PKCS8EncodedKeySpec(keyBytes)
    return KeyFactory.getInstance(CryptoConstants.ED25519).generatePrivate(keySpec)
}

fun loadEd25519PublicKey(path: Path): PublicKey {
    val keyBytes = readKeyBytes(path)
    val keySpec = X509EncodedKeySpec(keyBytes)
    return KeyFactory.getInstance(CryptoConstants.ED25519).generatePublic(keySpec)
}

private fun readKeyBytes(path: Path): ByteArray {
    val raw = Files.readString(path).trim()
    return if (raw.startsWith(CryptoConstants.PEM_BEGIN_PREFIX)) {
        decodePem(raw)
    } else {
        Base64.getDecoder().decode(raw)
    }
}

private fun decodePem(pem: String): ByteArray {
    val lines = pem.lines()
    val base64 = lines
        .filterNot { it.startsWith(CryptoConstants.PEM_BEGIN_PREFIX) || it.startsWith(CryptoConstants.PEM_END_PREFIX) }
        .joinToString("")
        .replace(WHITESPACE_REGEX, "")
    require(base64.isNotEmpty()) { "PEM payload is empty" }
    return Base64.getDecoder().decode(base64)
}
