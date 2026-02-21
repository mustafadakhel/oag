package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.policy.distribution.PolicyBundle
import com.mustafadakhel.oag.policy.distribution.PolicyBundleSigning
import com.mustafadakhel.oag.policy.distribution.encodeToPath
import com.mustafadakhel.oag.policy.distribution.loadEd25519PrivateKey
import com.mustafadakhel.oag.policy.distribution.signPolicyHash
import com.mustafadakhel.oag.policy.evaluation.hashPolicy
import com.mustafadakhel.oag.policy.lifecycle.loadAndValidatePolicy
import com.mustafadakhel.oag.policy.evaluation.normalize
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.nio.file.Path
import java.time.Instant

internal val BundleCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val policyPath = args.requireValue(CliFlags.POLICY)
    val outPath = args.requireValue(CliFlags.OUT)
    val signKeyPath = args.value(CliFlags.SIGN_KEY)
    val keyId = args.value(CliFlags.KEY_ID)

    val policy = loadAndValidatePolicy(Path.of(policyPath)).normalize()
    val policyHash = hashPolicy(policy)
    val signing = signKeyPath?.let { keyPath ->
        val privateKey = loadEd25519PrivateKey(Path.of(keyPath))
        PolicyBundleSigning(
            algorithm = CryptoConstants.ED25519,
            keyId = keyId,
            signature = signPolicyHash(policyHash, privateKey)
        )
    }

    val bundle = PolicyBundle(
        createdAt = Instant.now().toString(),
        policy = policy,
        policyHash = policyHash,
        signing = signing
    )

    encodeToPath(Path.of(outPath), PolicyBundle.serializer(), bundle)

    if (jsonMode) {
        out.println(cliJson.encodeToString(BundleJsonOutput(
            bundlePath = outPath,
            policyHash = policyHash,
            signed = signKeyPath != null
        )))
    }
    0
}

@Serializable
internal data class BundleJsonOutput(
    val ok: Boolean = true,
    @SerialName("bundle_path") val bundlePath: String,
    @SerialName("policy_hash") val policyHash: String,
    val signed: Boolean
)
