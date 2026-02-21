package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.policyService
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.nio.file.Path

internal val HashCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val verify = args.hasFlag(CliFlags.VERIFY)

    val policyService = if (verify) {
        val bundlePath = args.requireValue(CliFlags.BUNDLE)
        val publicKeyPath = args.requireValue(CliFlags.PUBLIC_KEY)
        PolicyService(
            policyPath = Path.of(bundlePath),
            policyPublicKeyPath = publicKeyPath,
            requireSignature = true
        )
    } else {
        val configDir = args.configDirPath()
        args.policyService(configDir)
    }

    val hash = policyService.currentHash

    if (jsonMode) {
        out.println(cliJson.encodeToString(HashJsonOutput(
            policyHash = hash,
            bundle = policyService.bundleInfoOutput()
        )))
        return@CliCommand 0
    }

    out.println(if (verify) "ok policy_hash=$hash" else hash)
    0
}

@Serializable
internal data class HashJsonOutput(
    val ok: Boolean = true,
    @SerialName("policy_hash") val policyHash: String,
    val bundle: BundleInfoOutput? = null
)
