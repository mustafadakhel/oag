package com.mustafadakhel.oag.policy.distribution

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.evaluation.hashPolicy
import com.mustafadakhel.oag.policy.lifecycle.resolveIncludes
import com.mustafadakhel.oag.policy.validation.PolicyValidationException
import com.mustafadakhel.oag.policy.evaluation.normalize
import com.mustafadakhel.oag.policy.validation.validatePolicy

import java.nio.file.Files
import java.nio.file.Path
import java.security.PublicKey

data class PolicySourceResult(
    val policy: PolicyDocument,
    val bundleInfo: PolicyBundleInfo?
)

fun loadAndValidatePolicySource(
    path: Path,
    publicKey: PublicKey?,
    requireSignature: Boolean
): PolicySourceResult {
    val text = Files.readString(path)
    if (isPolicyBundle(text)) {
        val bundle = decodeFromString(path, PolicyBundle.serializer(), text)
        val computedHash = hashPolicy(bundle.policy.normalize())
        require(computedHash == bundle.policyHash) {
            "policy bundle policy_hash does not match actual policy content"
        }
        validatePolicyBundle(bundle, publicKey, requireSignature)
        val policyErrors = validatePolicy(bundle.policy)
        if (policyErrors.isNotEmpty()) {
            throw PolicyValidationException(policyErrors)
        }
        val signing = bundle.signing
        val signatureStatus = when {
            signing == null -> SignatureStatus.NOT_SIGNED
            publicKey != null -> SignatureStatus.VERIFIED
            else -> SignatureStatus.SKIPPED
        }
        return PolicySourceResult(
            policy = bundle.policy,
            bundleInfo = PolicyBundleInfo(
                bundleVersion = bundle.bundleVersion,
                createdAt = bundle.createdAt,
                policyHash = bundle.policyHash,
                signingAlgorithm = signing?.algorithm,
                signingKeyId = signing?.keyId,
                signature = signing?.signature,
                signatureStatus = signatureStatus
            )
        )
    }

    val rawPolicy = decodeFromString(path, PolicyDocument.serializer(), text)
    val policy = if (!rawPolicy.includes.isNullOrEmpty()) {
        resolveIncludes(path)
    } else {
        rawPolicy
    }
    val errors = validatePolicy(policy)
    if (errors.isNotEmpty()) {
        throw PolicyValidationException(errors)
    }
    require(publicKey == null && !requireSignature) {
        "policy file at $path is not a bundle; cannot verify signature"
    }
    return PolicySourceResult(policy = policy, bundleInfo = null)
}

private val BUNDLE_KEY_PATTERN = Regex("""(?m)(?:^(?:bundle_version|bundleVersion)\s*:|"(?:bundle_version|bundleVersion)"\s*:)""")

private fun isPolicyBundle(text: String): Boolean =
    BUNDLE_KEY_PATTERN.containsMatchIn(text)

private fun validatePolicyBundle(
    bundle: PolicyBundle,
    publicKey: PublicKey?,
    requireSignature: Boolean
) {
    require(bundle.bundleVersion == PolicyBundle.CURRENT_BUNDLE_VERSION) { "policy bundle version must be ${PolicyBundle.CURRENT_BUNDLE_VERSION}" }
    require(bundle.policyHash.isNotBlank()) { "policy bundle policy_hash must not be blank" }
    val signing = bundle.signing
    require(!requireSignature || signing != null) {
        "policy bundle signature required but missing"
    }
    signing?.let {
        require(it.signature.isNotBlank()) { "policy bundle signature must not be blank" }
        require(it.algorithm.isNotBlank()) { "policy bundle algorithm must not be blank" }
        require(it.algorithm.equals(CryptoConstants.ED25519, ignoreCase = true)) { "policy bundle algorithm must be ${CryptoConstants.ED25519}" }
        if (publicKey != null) {
            val verified = try {
                verifyPolicyHash(bundle.policyHash, it.signature, publicKey)
            } catch (e: Exception) {
                throw IllegalArgumentException("policy bundle signature verification error: ${e.message}", e)
            }
            require(verified) { "policy bundle signature verification failed" }
        }
    }
}
