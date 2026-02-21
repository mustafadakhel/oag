package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class BundleInfoOutput(
    val version: Int,
    @SerialName("created_at") val createdAt: String?,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("signing_algorithm") val signingAlgorithm: String?,
    @SerialName("signing_key_id") val signingKeyId: String?,
    @SerialName("signature_status") val signatureStatus: String?
)

internal fun PolicyService.bundleInfoOutput(): BundleInfoOutput? {
    val info = currentBundleInfo ?: return null
    return BundleInfoOutput(
        version = info.bundleVersion,
        createdAt = info.createdAt,
        policyHash = info.policyHash,
        signingAlgorithm = info.signingAlgorithm,
        signingKeyId = info.signingKeyId,
        signatureStatus = info.signatureStatus.label()
    )
}
