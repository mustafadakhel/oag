package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.SCHEME_HTTP
import com.mustafadakhel.oag.SCHEME_HTTPS
import com.mustafadakhel.oag.VALID_PORT_RANGE
import com.mustafadakhel.oag.policy.support.parseIpRange
import com.mustafadakhel.oag.proxy.webhook.WebhookEventType
import com.mustafadakhel.oag.secrets.SecretProviderType
import com.mustafadakhel.oag.telemetry.OtelConfig
import com.mustafadakhel.oag.telemetry.OtelExporterType

import java.net.InetAddress
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

data class ProxyLogConfig(
    val path: String? = null,
    val maxSizeMb: Int = 0,
    val maxFiles: Int = ProxyDefaults.LOG_MAX_FILES,
    val compress: Boolean = false,
    val rotationInterval: String? = null
)

data class ProxyOAuth2Config(
    val tokenUrl: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val scope: String? = null
) {
    override fun toString() = "ProxyOAuth2Config(tokenUrl=$tokenUrl, clientId=$clientId, clientSecret=${if (clientSecret != null) "***" else "null"})"
}

data class ProxyTlsConfig(
    val inspect: Boolean = false,
    val caCertPath: String? = null,
    val mtlsCaCertPath: String? = null,
    val mtlsKeystorePath: String? = null,
    val mtlsKeystorePassword: String? = null
) {
    override fun toString() = "ProxyTlsConfig(inspect=$inspect, mtlsKeystorePassword=${if (mtlsKeystorePassword != null) "***" else "null"})"
}

data class ProxyAdminConfig(
    val port: Int? = null,
    val allowedIps: List<String> = emptyList(),
    val token: String? = null,
    val reloadCooldownMs: Long = ProxyDefaults.ADMIN_RELOAD_COOLDOWN_MS.toLong()
) {
    override fun toString() = "ProxyAdminConfig(port=$port, token=${if (token != null) "***" else "null"})"
}

data class ProxyWebhookConfig(
    val url: String? = null,
    val events: Set<WebhookEventType> = emptySet(),
    val timeoutMs: Int = ProxyDefaults.WEBHOOK_TIMEOUT_MS,
    val signingSecret: String? = null
) {
    override fun toString() = "ProxyWebhookConfig(url=$url, signingSecret=${if (signingSecret != null) "***" else "null"})"
}

data class ProxyPoolConfig(
    val maxIdle: Int = 0,
    val idleTimeoutMs: Long = ProxyDefaults.POOL_IDLE_TIMEOUT_MS.toLong()
)

data class ProxyCbConfig(
    val threshold: Int = ProxyDefaults.CIRCUIT_BREAKER_THRESHOLD,
    val resetMs: Long = ProxyDefaults.CIRCUIT_BREAKER_RESET_MS,
    val halfOpenProbes: Int = ProxyDefaults.CIRCUIT_BREAKER_HALF_OPEN_PROBES
)

data class ProxyPolicyConfig(
    val path: String,
    val publicKeyPath: String? = null,
    val requireSignature: Boolean = false,
    val url: String? = null,
    val fetchIntervalS: Long = ProxyDefaults.POLICY_FETCH_INTERVAL_S.toLong(),
    val watch: Boolean = false
)

data class ProxyNetworkConfig(
    val blockIpLiterals: Boolean = false,
    val blockPrivateResolvedIps: Boolean = false,
    val enforceRedirectPolicy: Boolean = false,
    val connectTimeoutMs: Int = ProxyDefaults.CONNECT_TIMEOUT_MS,
    val readTimeoutMs: Int = ProxyDefaults.READ_TIMEOUT_MS
)

data class ProxyIdentityConfig(
    val agentId: String? = null,
    val sessionId: String? = null,
    val agentSigningSecret: String? = null,
    val requireSignedHeaders: Boolean = false
) {
    override fun toString() =
        "ProxyIdentityConfig(agentId=$agentId, agentSigningSecret=${if (agentSigningSecret != null) "***" else "null"})"
}

data class ProxySecretConfig(
    val provider: SecretProviderType = SecretProviderType.ENV,
    val envPrefix: String = ProxyDefaults.SECRET_ENV_PREFIX,
    val fileDir: String? = null
)

data class ProxyConfig(
    val policy: ProxyPolicyConfig,
    val network: ProxyNetworkConfig = ProxyNetworkConfig(),
    val identity: ProxyIdentityConfig = ProxyIdentityConfig(),
    val secret: ProxySecretConfig = ProxySecretConfig(),
    val listenHost: String = ProxyDefaults.LISTEN_HOST,
    val listenPort: Int = ProxyDefaults.LISTEN_PORT,
    val oagVersion: String = ProxyDefaults.OAG_VERSION,
    val maxThreads: Int = ProxyDefaults.MAX_THREADS,
    val oauth2: ProxyOAuth2Config = ProxyOAuth2Config(),
    val dryRun: Boolean = false,
    val otelConfig: OtelConfig = OtelConfig(),
    val verbose: Boolean = false,
    val tls: ProxyTlsConfig = ProxyTlsConfig(),
    val log: ProxyLogConfig = ProxyLogConfig(),
    val admin: ProxyAdminConfig = ProxyAdminConfig(),
    val cb: ProxyCbConfig = ProxyCbConfig(),
    val drainTimeoutMs: Long = ProxyDefaults.DRAIN_TIMEOUT_MS.toLong(),
    val injectRequestId: Boolean = false,
    val requestIdHeader: String = ProxyDefaults.REQUEST_ID_HEADER,
    val pool: ProxyPoolConfig = ProxyPoolConfig(),
    val webhook: ProxyWebhookConfig = ProxyWebhookConfig(),
    val integrityCheckIntervalS: Long = 0,
    val velocitySpikeThreshold: Double = 0.0,
    val pluginProviders: List<String> = emptyList()
) {
    override fun toString(): String = buildString {
        append("ProxyConfig(")
        append("policy=$policy, ")
        append("listenHost=$listenHost, ")
        append("listenPort=$listenPort, ")
        append("dryRun=$dryRun, ")
        append("secret=$secret, ")
        append("identity=$identity, ")
        append("oauth2=$oauth2, ")
        append("tls=$tls, ")
        append("admin=$admin, ")
        append("webhook=$webhook")
        append(")")
    }
}

internal fun ProxyConfig.toFingerprintString(): String = buildString {
    append("Policy|${policy.path}|${policy.publicKeyPath}|${policy.requireSignature}|${policy.url}|${policy.fetchIntervalS}|${policy.watch}")
    append("|Network|${network.blockIpLiterals}|${network.blockPrivateResolvedIps}|${network.enforceRedirectPolicy}|${network.connectTimeoutMs}|${network.readTimeoutMs}")
    append("|Identity|${identity.agentId}|${identity.sessionId}|${identity.agentSigningSecret}|${identity.requireSignedHeaders}")
    append("|Secret|${secret.provider}|${secret.envPrefix}|${secret.fileDir}")
    append("|TLS|${tls.inspect}|${tls.caCertPath}|${tls.mtlsCaCertPath}|${tls.mtlsKeystorePath}|${tls.mtlsKeystorePassword}")
    append("|Admin|${admin.port}|${admin.allowedIps}|${admin.token}|${admin.reloadCooldownMs}")
    append("|Webhook|${webhook.url}|${webhook.events}|${webhook.timeoutMs}|${webhook.signingSecret}")
    append("|OAuth2|${oauth2.tokenUrl}|${oauth2.clientId}|${oauth2.clientSecret}|${oauth2.scope}")
    append("|Pool|${pool.maxIdle}|${pool.idleTimeoutMs}")
    append("|CB|${cb.threshold}|${cb.resetMs}|${cb.halfOpenProbes}")
    append("|Log|${log.path}|${log.maxSizeMb}|${log.maxFiles}|${log.compress}|${log.rotationInterval}")
    append("|Otel|${otelConfig.exporter}|${otelConfig.endpoint}|${otelConfig.headers}|${otelConfig.timeoutMs}|${otelConfig.serviceName}")
    append("|$listenHost|$listenPort|$oagVersion|$maxThreads|$dryRun|$verbose")
    append("|$drainTimeoutMs|$injectRequestId|$requestIdHeader|$integrityCheckIntervalS|$velocitySpikeThreshold")
    append("|$pluginProviders")
}

fun validateProxyConfig(config: ProxyConfig) {
    validatePolicyConfig(config.policy)
    validateNetworkConfig(config.network)
    validateIdentityConfig(config.identity)
    validateSecretConfig(config.secret)
    config.pluginProviders.forEachIndexed { i, name ->
        require(name.isNotBlank()) { "pluginProviders[$i] must not be blank" }
    }
    require(config.pluginProviders.distinct().size == config.pluginProviders.size) { "pluginProviders must not contain duplicates" }
    require(config.listenHost.isNotBlank()) { "listenHost must not be blank" }
    require(config.listenPort in VALID_PORT_RANGE) { "listenPort must be between 1 and 65535" }
    require(config.maxThreads > 0) { "maxThreads must be greater than 0" }
    if (config.otelConfig.enabled) {
        require(config.otelConfig.timeoutMs > 0) { "otelTimeoutMs must be greater than 0" }
        require(config.otelConfig.serviceName.isNotBlank()) { "otelServiceName must not be blank" }
        val exporter = config.otelConfig.exporter
        if (exporter == OtelExporterType.OTLP_HTTP || exporter == OtelExporterType.OTLP_GRPC) {
            val endpoint = config.otelConfig.endpoint?.trim()
            require(!endpoint.isNullOrEmpty()) { "otelEndpoint must not be blank for OTLP exporters" }
            val uri = runCatching { URI(endpoint) }.getOrNull()
            require(uri != null && !uri.scheme.isNullOrBlank()) { "otelEndpoint must include a scheme" }
            val scheme = uri.scheme.lowercase(Locale.ROOT)
            require(scheme == SCHEME_HTTP || scheme == SCHEME_HTTPS) { "otelEndpoint must use http or https" }
        }
        config.otelConfig.headers.forEach { (key, value) ->
            require(key.isNotBlank()) { "otel header key must not be blank" }
            require(value.isNotBlank()) { "otel header value must not be blank" }
        }
    }
    if (config.tls.caCertPath != null) {
        require(config.tls.caCertPath.isNotBlank()) { "tlsCaCertPath must not be blank" }
    }
    if (config.tls.mtlsCaCertPath != null) {
        require(config.tls.mtlsCaCertPath.isNotBlank()) { "mtlsCaCertPath must not be blank" }
        require(config.tls.mtlsKeystorePath != null) { "mtlsKeystorePath must be set when mtlsCaCertPath is set" }
    }
    if (config.tls.mtlsKeystorePath != null) {
        require(config.tls.mtlsKeystorePath.isNotBlank()) { "mtlsKeystorePath must not be blank" }
        val keystorePath = Path.of(config.tls.mtlsKeystorePath)
        require(Files.exists(keystorePath)) { "mtlsKeystorePath does not exist: ${config.tls.mtlsKeystorePath}" }
        require(config.tls.mtlsCaCertPath != null) { "mtlsCaCertPath must be set when mtlsKeystorePath is set — omitting it would accept any public-CA client certificate" }
    }
    if (config.log.path != null) {
        require(config.log.path.isNotBlank()) { "logPath must not be blank" }
    }
    for (entry in config.admin.allowedIps) {
        runCatching {
            if (entry.contains("/")) {
                parseIpRange(entry)
            } else {
                InetAddress.getByName(entry)
            }
        }.onFailure { cause ->
            throw IllegalArgumentException("Invalid admin allowed IP: $entry", cause)
        }
    }
    if (config.log.path != null) {
        val logPath = Path.of(config.log.path)
        if (Files.exists(logPath)) {
            require(!Files.isDirectory(logPath)) { "logPath must not be a directory: ${config.log.path}" }
        }
        logPath.parent?.let { parent ->
            if (Files.exists(parent)) {
                require(Files.isDirectory(parent)) { "logPath parent must be a directory: $parent" }
            }
        }
    }
}

private fun validatePolicyConfig(policy: ProxyPolicyConfig) {
    require(policy.path.isNotBlank()) { "policyPath must not be blank" }
    if (policy.requireSignature) {
        require(!policy.publicKeyPath.isNullOrBlank()) { "policyPublicKeyPath must be set when policyRequireSignature is true" }
    }
    val policyPath = Path.of(policy.path)
    require(Files.exists(policyPath)) { "policyPath does not exist: ${policy.path}" }
    require(Files.isRegularFile(policyPath)) { "policyPath is not a file: ${policy.path}" }
    if (policy.publicKeyPath != null) {
        val publicKeyPath = Path.of(policy.publicKeyPath)
        require(Files.exists(publicKeyPath)) { "policyPublicKeyPath does not exist: ${policy.publicKeyPath}" }
        require(Files.isRegularFile(publicKeyPath)) { "policyPublicKeyPath is not a file: ${policy.publicKeyPath}" }
    }
}

private fun validateNetworkConfig(network: ProxyNetworkConfig) {
    require(network.connectTimeoutMs > 0) { "connectTimeoutMs must be greater than 0" }
    require(network.readTimeoutMs > 0) { "readTimeoutMs must be greater than 0" }
}

private fun validateIdentityConfig(identity: ProxyIdentityConfig) {
    if (identity.requireSignedHeaders) {
        require(!identity.agentSigningSecret.isNullOrBlank()) { "agentSigningSecret must be set when requireSignedHeaders is true" }
    }
}

private fun validateSecretConfig(secret: ProxySecretConfig) {
    require(secret.envPrefix.isNotBlank()) { "secretEnvPrefix must not be blank" }
    if (secret.provider == SecretProviderType.FILE) {
        val secretDir = secret.fileDir?.trim()
        require(!secretDir.isNullOrEmpty()) { "secretFileDir must not be blank when secretProvider is file" }
        val secretPath = Path.of(secretDir)
        require(Files.exists(secretPath)) { "secretFileDir does not exist: $secretDir" }
        require(Files.isDirectory(secretPath)) { "secretFileDir is not a directory: $secretDir" }
    }
}
