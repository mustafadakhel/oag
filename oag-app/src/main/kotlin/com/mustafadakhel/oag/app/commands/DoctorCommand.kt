package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.parseOtelConfig
import com.mustafadakhel.oag.app.parseSecretProvider
import com.mustafadakhel.oag.app.resolvePolicyPath
import com.mustafadakhel.oag.app.resolveSecretDir
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.proxy.ProxyConfig
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.proxy.ProxyNetworkConfig
import com.mustafadakhel.oag.proxy.ProxyPolicyConfig
import com.mustafadakhel.oag.proxy.ProxySecretConfig
import com.mustafadakhel.oag.proxy.validateProxyConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.nio.file.Path

internal val DoctorCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val verboseMode = args.hasFlag(CliFlags.VERBOSE)
    val configDir = args.configDirPath()
    val secretProvider = args.parseSecretProvider()
    val config = ProxyConfig(
        policy = ProxyPolicyConfig(
            path = args.resolvePolicyPath(configDir, allowPositional = false),
            publicKeyPath = args.value(CliFlags.POLICY_PUBLIC_KEY),
            requireSignature = args.hasFlag(CliFlags.POLICY_REQUIRE_SIGNATURE)
        ),
        network = ProxyNetworkConfig(
            blockIpLiterals = args.hasFlag(CliFlags.BLOCK_IP_LITERALS),
            blockPrivateResolvedIps = args.hasFlag(CliFlags.BLOCK_PRIVATE_RESOLVED_IPS),
            enforceRedirectPolicy = args.hasFlag(CliFlags.ENFORCE_REDIRECT_POLICY),
            connectTimeoutMs = args.intValue(CliFlags.CONNECT_TIMEOUT_MS, ProxyDefaults.CONNECT_TIMEOUT_MS),
            readTimeoutMs = args.intValue(CliFlags.READ_TIMEOUT_MS, ProxyDefaults.READ_TIMEOUT_MS)
        ),
        secret = ProxySecretConfig(
            provider = secretProvider,
            envPrefix = args.value(CliFlags.SECRET_PREFIX) ?: ProxyDefaults.SECRET_ENV_PREFIX,
            fileDir = args.resolveSecretDir(configDir, secretProvider)
        ),
        listenPort = args.intValue(CliFlags.PORT, ProxyDefaults.LISTEN_PORT),
        maxThreads = args.intValue(CliFlags.MAX_THREADS, ProxyDefaults.MAX_THREADS),
        otelConfig = args.parseOtelConfig()
    )
    validateProxyConfig(config)
    val policyService = PolicyService(
        policyPath = Path.of(config.policy.path),
        policyPublicKeyPath = config.policy.publicKeyPath,
        requireSignature = config.policy.requireSignature
    )
    if (jsonMode) {
        out.println(cliJson.encodeToString(DoctorJsonOutput(
            policyHash = policyService.currentHash,
            policyPath = config.policy.path,
            effectiveConfig = if (verboseMode) config.toEffectiveConfigJson() else null,
            bundle = policyService.bundleInfoOutput()
        )))
    } else {
        out.println("ok")
    }
    0
}

private fun ProxyConfig.toEffectiveConfigJson() = EffectiveConfigJson(
    listenHost = listenHost,
    listenPort = listenPort,
    maxThreads = maxThreads,
    dryRun = dryRun,
    blockIpLiterals = network.blockIpLiterals,
    enforceRedirectPolicy = network.enforceRedirectPolicy,
    blockPrivateResolvedIps = network.blockPrivateResolvedIps,
    connectTimeoutMs = network.connectTimeoutMs,
    readTimeoutMs = network.readTimeoutMs,
    secretEnvPrefix = secret.envPrefix,
    secretProvider = secret.provider.label(),
    secretFileDir = secret.fileDir,
    policyPublicKeyPath = policy.publicKeyPath,
    policyRequireSignature = policy.requireSignature,
    otelExporter = otelConfig.exporter.label(),
    otelEndpoint = otelConfig.endpoint,
    otelHeadersKeys = otelConfig.headers.keys.sorted(),
    otelTimeoutMs = otelConfig.timeoutMs,
    otelServiceName = otelConfig.serviceName
)

@Serializable
internal data class DoctorJsonOutput(
    val ok: Boolean = true,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("policy_path") val policyPath: String,
    @SerialName("effective_config") val effectiveConfig: EffectiveConfigJson? = null,
    val bundle: BundleInfoOutput? = null
)

@Serializable
internal data class EffectiveConfigJson(
    @SerialName("listen_host") val listenHost: String,
    @SerialName("listen_port") val listenPort: Int,
    @SerialName("max_threads") val maxThreads: Int,
    @SerialName("dry_run") val dryRun: Boolean,
    @SerialName("block_ip_literals") val blockIpLiterals: Boolean,
    @SerialName("enforce_redirect_policy") val enforceRedirectPolicy: Boolean,
    @SerialName("block_private_resolved_ips") val blockPrivateResolvedIps: Boolean,
    @SerialName("connect_timeout_ms") val connectTimeoutMs: Int,
    @SerialName("read_timeout_ms") val readTimeoutMs: Int,
    @SerialName("secret_env_prefix") val secretEnvPrefix: String,
    @SerialName("secret_provider") val secretProvider: String,
    @SerialName("secret_file_dir") val secretFileDir: String?,
    @SerialName("policy_public_key_path") val policyPublicKeyPath: String?,
    @SerialName("policy_require_signature") val policyRequireSignature: Boolean,
    @SerialName("otel_exporter") val otelExporter: String,
    @SerialName("otel_endpoint") val otelEndpoint: String?,
    @SerialName("otel_headers_keys") val otelHeadersKeys: List<String>,
    @SerialName("otel_timeout_ms") val otelTimeoutMs: Int,
    @SerialName("otel_service_name") val otelServiceName: String
)
