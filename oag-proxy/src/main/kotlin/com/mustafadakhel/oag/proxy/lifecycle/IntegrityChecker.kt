package com.mustafadakhel.oag.proxy.lifecycle

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.proxy.ProxyConfig
import com.mustafadakhel.oag.proxy.toFingerprintString

import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

internal enum class IntegrityStatus {
    PASS, DRIFT_DETECTED
}

internal data class IntegrityResult(
    val status: IntegrityStatus,
    val policyHashMatch: Boolean,
    val configFingerprintMatch: Boolean
)

internal class IntegrityChecker(
    private val policyService: PolicyService,
    expectedPolicyHash: String,
    private val initialConfigFingerprint: String
) {
    private val expectedPolicyHash = AtomicReference(expectedPolicyHash)

    fun checkWithFingerprint(currentFingerprint: String): IntegrityResult {
        val currentHash = policyService.currentHash
        val policyMatch = MessageDigest.isEqual(
            currentHash.toByteArray(Charsets.UTF_8),
            this.expectedPolicyHash.get().toByteArray(Charsets.UTF_8)
        )
        val configMatch = MessageDigest.isEqual(
            currentFingerprint.toByteArray(Charsets.UTF_8),
            initialConfigFingerprint.toByteArray(Charsets.UTF_8)
        )
        return IntegrityResult(
            status = if (policyMatch && configMatch) IntegrityStatus.PASS else IntegrityStatus.DRIFT_DETECTED,
            policyHashMatch = policyMatch,
            configFingerprintMatch = configMatch
        )
    }

    fun updateExpectedPolicyHash(newHash: String) {
        expectedPolicyHash.set(newHash)
    }
}

internal fun computeConfigFingerprint(config: ProxyConfig): String {
    val digest = MessageDigest.getInstance(CryptoConstants.SHA_256)
    val hash = digest.digest(config.toFingerprintString().toByteArray(Charsets.UTF_8))
    return hash.toHexString()
}
