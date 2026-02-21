package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.policy.core.PolicyDocument

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyBundle(
    @SerialName("bundle_version") val bundleVersion: Int = CURRENT_BUNDLE_VERSION,
    @SerialName("created_at") val createdAt: String? = null,
    val policy: PolicyDocument,
    @SerialName("policy_hash") val policyHash: String,
    val signing: PolicyBundleSigning? = null
) {
    companion object {
        const val CURRENT_BUNDLE_VERSION = 1
    }
}

@Serializable
data class PolicyBundleSigning(
    val algorithm: String,
    @SerialName("key_id") val keyId: String? = null,
    val signature: String
)

enum class SignatureStatus {
    NOT_SIGNED,
    VERIFIED,
    SKIPPED
}

data class PolicyBundleInfo(
    val bundleVersion: Int,
    val createdAt: String?,
    val policyHash: String,
    val signingAlgorithm: String?,
    val signingKeyId: String?,
    val signature: String?,
    val signatureStatus: SignatureStatus
)
