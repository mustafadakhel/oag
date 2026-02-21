package com.mustafadakhel.oag

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun computeHmacSha256(secret: String, data: ByteArray): String {
    val mac = Mac.getInstance(CryptoConstants.HMAC_SHA_256)
    mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), CryptoConstants.HMAC_SHA_256))
    return mac.doFinal(data).toHexString()
}
