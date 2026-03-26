package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliDefaults
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.InvalidArgumentException
import com.mustafadakhel.oag.app.ParsedArgs
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.parseOtelConfig
import com.mustafadakhel.oag.app.parseSecretProvider
import com.mustafadakhel.oag.app.resolvePolicyPath
import com.mustafadakhel.oag.app.resolveSecretDir
import com.mustafadakhel.oag.proxy.ProxyAdminConfig
import com.mustafadakhel.oag.proxy.ProxyCbConfig
import com.mustafadakhel.oag.proxy.ProxyConfig
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.proxy.ProxyIdentityConfig
import com.mustafadakhel.oag.proxy.ProxyNetworkConfig
import com.mustafadakhel.oag.proxy.ProxyPolicyConfig
import com.mustafadakhel.oag.proxy.ProxySecretConfig
import com.mustafadakhel.oag.proxy.ProxyLogConfig
import com.mustafadakhel.oag.proxy.ProxyOAuth2Config
import com.mustafadakhel.oag.proxy.ProxyPoolConfig
import com.mustafadakhel.oag.proxy.ProxyTlsConfig
import com.mustafadakhel.oag.proxy.ProxyWebhookConfig
import com.mustafadakhel.oag.proxy.runProxy
import com.mustafadakhel.oag.proxy.webhook.WebhookEventType

import java.nio.file.Path

internal val RunCommand = CliCommand { args, _ ->
    val configDir = args.configDirPath()
    val secretProvider = args.parseSecretProvider()

    runProxy(
        ProxyConfig(
            policy = ProxyPolicyConfig(
                path = args.resolvePolicyPath(configDir, allowPositional = false),
                publicKeyPath = args.value(CliFlags.POLICY_PUBLIC_KEY),
                requireSignature = args.hasFlag(CliFlags.POLICY_REQUIRE_SIGNATURE),
                url = args.value(CliFlags.POLICY_URL),
                fetchIntervalS = args.longValue(CliFlags.POLICY_FETCH_INTERVAL_S, ProxyDefaults.POLICY_FETCH_INTERVAL_S.toLong()),
                watch = args.hasFlag(CliFlags.WATCH)
            ),
            network = ProxyNetworkConfig(
                blockIpLiterals = args.hasFlag(CliFlags.BLOCK_IP_LITERALS),
                blockPrivateResolvedIps = args.hasFlag(CliFlags.BLOCK_PRIVATE_RESOLVED_IPS),
                enforceRedirectPolicy = args.hasFlag(CliFlags.ENFORCE_REDIRECT_POLICY),
                connectTimeoutMs = args.intValue(CliFlags.CONNECT_TIMEOUT_MS, ProxyDefaults.CONNECT_TIMEOUT_MS),
                readTimeoutMs = args.intValue(CliFlags.READ_TIMEOUT_MS, ProxyDefaults.READ_TIMEOUT_MS)
            ),
            identity = ProxyIdentityConfig(
                agentId = args.value(CliFlags.AGENT),
                sessionId = args.value(CliFlags.SESSION),
                agentSigningSecret = args.value(CliFlags.AGENT_SIGNING_SECRET),
                requireSignedHeaders = args.hasFlag(CliFlags.REQUIRE_SIGNED_HEADERS)
            ),
            secret = ProxySecretConfig(
                provider = secretProvider,
                envPrefix = args.value(CliFlags.SECRET_PREFIX) ?: ProxyDefaults.SECRET_ENV_PREFIX,
                fileDir = args.resolveSecretDir(configDir, secretProvider)
            ),
            listenPort = args.intValue(CliFlags.PORT, ProxyDefaults.LISTEN_PORT),
            log = args.buildLogConfig(configDir),
            maxThreads = args.intValue(CliFlags.MAX_THREADS, ProxyDefaults.MAX_THREADS),
            oauth2 = args.buildOAuth2Config(),
            otelConfig = args.parseOtelConfig(),
            dryRun = args.hasFlag(CliFlags.DRY_RUN),
            verbose = args.hasFlag(CliFlags.VERBOSE),
            tls = args.buildTlsConfig(),
            admin = args.buildAdminConfig(),
            cb = args.buildCbConfig(),
            drainTimeoutMs = args.longValue(CliFlags.DRAIN_TIMEOUT_MS, ProxyDefaults.DRAIN_TIMEOUT_MS.toLong()),
            injectRequestId = args.hasFlag(CliFlags.INJECT_REQUEST_ID),
            requestIdHeader = args.value(CliFlags.REQUEST_ID_HEADER) ?: ProxyDefaults.REQUEST_ID_HEADER,
            pool = args.buildPoolConfig(),
            webhook = args.buildWebhookConfig(),
            integrityCheckIntervalS = args.longValue(CliFlags.INTEGRITY_CHECK_INTERVAL_S, 0L),
            velocitySpikeThreshold = args.doubleValue(CliFlags.VELOCITY_SPIKE_THRESHOLD, 0.0),
            pluginProviders = args.commaSeparatedList(CliFlags.PLUGIN_PROVIDER)
        )
    )
    0
}

private fun ParsedArgs.buildLogConfig(configDir: Path?): ProxyLogConfig = ProxyLogConfig(
    path = value(CliFlags.LOG)
        ?: configDir?.resolve(CliDefaults.LOGS_DIR)?.resolve(CliDefaults.AUDIT_FILE)?.toString(),
    maxSizeMb = intValue(CliFlags.LOG_MAX_SIZE_MB, 0),
    maxFiles = intValue(CliFlags.LOG_MAX_FILES, ProxyDefaults.LOG_MAX_FILES),
    compress = hasFlag(CliFlags.LOG_COMPRESS),
    rotationInterval = value(CliFlags.LOG_ROTATION_INTERVAL)
)

private fun ParsedArgs.buildOAuth2Config(): ProxyOAuth2Config = ProxyOAuth2Config(
    tokenUrl = value(CliFlags.OAUTH2_TOKEN_URL),
    clientId = value(CliFlags.OAUTH2_CLIENT_ID),
    clientSecret = value(CliFlags.OAUTH2_CLIENT_SECRET),
    scope = value(CliFlags.OAUTH2_SCOPE)
)

private fun ParsedArgs.buildTlsConfig(): ProxyTlsConfig = ProxyTlsConfig(
    inspect = hasFlag(CliFlags.TLS_INSPECT),
    caCertPath = value(CliFlags.TLS_CA_CERT_PATH),
    mtlsCaCertPath = value(CliFlags.MTLS_CA_CERT),
    mtlsKeystorePath = value(CliFlags.MTLS_KEYSTORE),
    mtlsKeystorePassword = value(CliFlags.MTLS_KEYSTORE_PASSWORD) ?: System.getenv("OAG_MTLS_KEYSTORE_PASSWORD")
)

private fun ParsedArgs.buildAdminConfig(): ProxyAdminConfig = ProxyAdminConfig(
    port = optionalInt(CliFlags.ADMIN_PORT),
    allowedIps = commaSeparatedList(CliFlags.ADMIN_ALLOWED_IPS),
    token = value(CliFlags.ADMIN_TOKEN) ?: System.getenv("OAG_ADMIN_TOKEN"),
    reloadCooldownMs = longValue(CliFlags.ADMIN_RELOAD_COOLDOWN_MS, ProxyDefaults.ADMIN_RELOAD_COOLDOWN_MS.toLong())
)

private fun ParsedArgs.buildCbConfig(): ProxyCbConfig = ProxyCbConfig(
    threshold = intValue(CliFlags.CIRCUIT_BREAKER_THRESHOLD, ProxyDefaults.CIRCUIT_BREAKER_THRESHOLD),
    resetMs = longValue(CliFlags.CIRCUIT_BREAKER_RESET_MS, ProxyDefaults.CIRCUIT_BREAKER_RESET_MS),
    halfOpenProbes = intValue(CliFlags.CIRCUIT_BREAKER_HALF_OPEN_PROBES, ProxyDefaults.CIRCUIT_BREAKER_HALF_OPEN_PROBES)
)

private fun ParsedArgs.buildPoolConfig(): ProxyPoolConfig = ProxyPoolConfig(
    maxIdle = intValue(CliFlags.POOL_MAX_IDLE, 0),
    idleTimeoutMs = longValue(CliFlags.POOL_IDLE_TIMEOUT_MS, ProxyDefaults.POOL_IDLE_TIMEOUT_MS.toLong())
)

private fun ParsedArgs.buildWebhookConfig(): ProxyWebhookConfig = ProxyWebhookConfig(
    url = value(CliFlags.WEBHOOK_URL),
    events = commaSeparatedSet(CliFlags.WEBHOOK_EVENTS).map { label ->
        WebhookEventType.fromLabel(label) ?: throw InvalidArgumentException.entry(CliFlags.WEBHOOK_EVENTS, label)
    }.toSet(),
    timeoutMs = intValue(CliFlags.WEBHOOK_TIMEOUT_MS, ProxyDefaults.WEBHOOK_TIMEOUT_MS),
    signingSecret = value(CliFlags.WEBHOOK_SIGNING_SECRET)
)
