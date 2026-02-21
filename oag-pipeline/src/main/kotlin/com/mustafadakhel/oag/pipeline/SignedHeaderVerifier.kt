package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.MS_PER_SECOND
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.http.HttpConstants

import kotlin.math.abs

import java.security.MessageDigest

private const val HMAC_PREFIX = CryptoConstants.SIGNATURE_PREFIX_HMAC_SHA256
private const val MAX_CLOCK_SKEW_SECONDS = 300L

const val REASON_MISSING_SIGNATURE = "missing_signature_header"
const val REASON_MISSING_TIMESTAMP = "missing_timestamp_header"
const val REASON_INVALID_TIMESTAMP = "invalid_timestamp"
const val REASON_TIMESTAMP_EXPIRED = "timestamp_expired"
const val REASON_UNSUPPORTED_ALGORITHM = "unsupported_signature_algorithm"
const val REASON_CANONICAL_INJECTION = "canonical_injection"
const val REASON_SIGNATURE_MISMATCH = "signature_mismatch"

data class VerificationResult(
    val valid: Boolean,
    val agentId: String? = null,
    val reason: String? = null
)

fun verifySignedHeaders(
    headers: Map<String, String>,
    method: String,
    host: String,
    path: String,
    secret: String,
    nowEpochSeconds: Long = System.currentTimeMillis() / MS_PER_SECOND
): VerificationResult {
    val signatureHeader = headers[HttpConstants.OAG_SIGNATURE] ?: return VerificationResult(
        valid = false, reason = REASON_MISSING_SIGNATURE
    )
    val timestamp = headers[HttpConstants.OAG_TIMESTAMP] ?: return VerificationResult(
        valid = false, reason = REASON_MISSING_TIMESTAMP
    )
    val epochSeconds = timestamp.toLongOrNull() ?: return VerificationResult(
        valid = false, reason = REASON_INVALID_TIMESTAMP
    )
    if (abs(nowEpochSeconds - epochSeconds) > MAX_CLOCK_SKEW_SECONDS) {
        return VerificationResult(valid = false, reason = REASON_TIMESTAMP_EXPIRED)
    }
    if (!signatureHeader.startsWith(HMAC_PREFIX)) {
        return VerificationResult(valid = false, reason = REASON_UNSUPPORTED_ALGORITHM)
    }
    val providedHex = signatureHeader.removePrefix(HMAC_PREFIX)
    if (method.contains('\n') || host.contains('\n') || path.contains('\n') || timestamp.contains('\n')) {
        return VerificationResult(valid = false, reason = REASON_CANONICAL_INJECTION)
    }
    val canonical = "$method\n$host\n$path\n$timestamp"
    val expectedHex = computeHmacSha256(secret, canonical.toByteArray(Charsets.UTF_8))
    if (!MessageDigest.isEqual(providedHex.toByteArray(Charsets.UTF_8), expectedHex.toByteArray(Charsets.UTF_8))) {
        return VerificationResult(valid = false, reason = REASON_SIGNATURE_MISMATCH)
    }
    val agentId = headers[HttpConstants.OAG_AGENT_ID]
    return VerificationResult(valid = true, agentId = agentId)
}
