package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.policy.core.PolicyDocument

import kotlinx.serialization.json.Json

import java.security.MessageDigest

private val canonicalJson = Json {
    encodeDefaults = true
    explicitNulls = true
    prettyPrint = false
}

fun hashPolicy(policy: PolicyDocument): String {
    val canonical = canonicalizePolicy(policy)
    val bytes = canonicalJson.encodeToString(PolicyDocument.serializer(), canonical).toByteArray(Charsets.UTF_8)
    val digest = MessageDigest.getInstance(CryptoConstants.SHA_256).digest(bytes)
    return digest.toHexString()
}
