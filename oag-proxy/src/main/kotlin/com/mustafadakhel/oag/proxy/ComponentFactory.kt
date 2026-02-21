package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.CryptoConstants
import com.mustafadakhel.oag.audit.AuditCircuitBreakerEvent
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.audit.buildAuditOutputStream
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.NetworkConfig
import com.mustafadakhel.oag.pipeline.RequestIdConfig
import com.mustafadakhel.oag.pipeline.SecurityConfig
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.pipeline.webhookData
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.ConnectionPool
import com.mustafadakhel.oag.enforcement.CircuitState
import com.mustafadakhel.oag.proxy.tls.CaBundle
import com.mustafadakhel.oag.proxy.tls.generateCaBundle
import com.mustafadakhel.oag.proxy.tls.buildMtlsServerSocketFactory
import com.mustafadakhel.oag.proxy.webhook.WebhookConfig
import com.mustafadakhel.oag.proxy.webhook.WebhookPayload
import com.mustafadakhel.oag.pipeline.WebhookPayloadKeys
import com.mustafadakhel.oag.proxy.webhook.WebhookSender
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.secrets.SecretProviderConfig
import com.mustafadakhel.oag.secrets.buildSecretProvider
import com.mustafadakhel.oag.telemetry.DebugLogger

import com.mustafadakhel.oag.telemetry.buildOagTracer

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.proxy.pipeline.buildFullProxyHandler
import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.telemetry.OagMetrics
import com.mustafadakhel.oag.telemetry.OagTracer
import com.mustafadakhel.oag.telemetry.OtelAuditLogger

import javax.net.ssl.SSLServerSocketFactory

/**
 * Transfers lifecycle-bound resources from [buildComponents] to [ProxyRuntime].
 * Not a service locator — fields are consumed by specific lifecycle owners (admin server,
 * signal handlers, background tasks). DataBudgetTracker and TokenBudgetTracker are created
 * inline in [buildFullProxyHandler] and not stored here because their state is request-scoped
 * and does not need admin introspection.
 */
internal class ProxyComponents(
    val debugLogger: DebugLogger,
    val auditLogger: AuditLogger,
    val otelLogger: OtelAuditLogger?,
    val tracer: OagTracer?,
    val policyService: PolicyService,
    val webhookSender: WebhookSender?,
    val webhookScope: CoroutineScope?,
    val webhookCallback: WebhookCallback?,
    val oagMetrics: OagMetrics,
    val circuitBreakerRegistry: CircuitBreakerRegistry,
    val rateLimiterRegistry: RateLimiterRegistry,
    val connectionPool: ConnectionPool?,
    val caBundle: CaBundle?,
    val hostCertificateCache: HostCertificateCache?,
    val sslServerSocketFactory: SSLServerSocketFactory?,
    val secretMaterializer: SecretMaterializer,
    val sessionRequestTracker: SessionRequestTracker?,
    val detectorRegistry: DetectorRegistry,
    val handler: ProxyHandler,
    val handlerConfig: HandlerConfig
)

internal fun buildComponents(config: ProxyConfig): ProxyComponents {
    val debugLogger: DebugLogger = if (config.verbose) DebugLogger(System.err) else DebugLogger.NOOP
    val otelLogger: OtelAuditLogger? = config.otelConfig.takeIf { it.enabled }?.let { OtelAuditLogger(it, config.oagVersion) }
    val tracer: OagTracer? = buildOagTracer(config.otelConfig, config.oagVersion)
    val oagMetrics = OagMetrics()
    val auditLogger = AuditLogger(
        outputStream = buildProxyAuditOutputStream(config, debugLogger::log),
        externalSink = otelLogger,
        closeOutputStream = config.log.path != null,
        onError = debugLogger::log,
        onDrop = oagMetrics::recordAuditDropped
    )
    val policyService = PolicyService(
        policyPath = java.nio.file.Path.of(config.policy.path),
        policyPublicKeyPath = config.policy.publicKeyPath,
        requireSignature = config.policy.requireSignature,
        onRegexError = debugLogger::log
    )
    val webhookSender = buildWebhookSender(config, debugLogger)
    val webhookScope: CoroutineScope? = webhookSender?.let { CoroutineScope(SupervisorJob() + Dispatchers.IO) }
    val webhookCallback = buildWebhookCallback(webhookSender, webhookScope)
    val circuitBreakerRegistry = buildCircuitBreakerRegistry(config, debugLogger, auditLogger, webhookCallback)
    val rateLimiterRegistry = RateLimiterRegistry().apply {
        policyService.rateLimitConfigs().forEach { configure(it.ruleId, it.requestsPerSecond, it.burst) }
    }
    val connectionPool = buildConnectionPool(config)
    val caBundle = buildCaBundle(config, debugLogger)
    val hostCertificateCache: HostCertificateCache? = caBundle?.let { HostCertificateCache(it) }
    val sslServerSocketFactory = buildMtlsSslFactory(config)
    val handlerConfig = buildHandlerConfig(config)
    val secretMaterializer = buildSecretMaterializer(config)
    val sessionRequestTracker: SessionRequestTracker? = config.identity.sessionId?.let { SessionRequestTracker() }
    val detectorRegistry = DetectorRegistry.loadFromClassNames(
        classNames = config.pluginProviders,
        onError = debugLogger::log
    )
    if (detectorRegistry.providers.isNotEmpty()) {
        debugLogger.log("plugin detectors loaded: ${detectorRegistry.providers.joinToString { "${it.id} (${it.description})" }}")
    }

    val handler = buildFullProxyHandler(
        config = handlerConfig,
        policyService = policyService,
        secretMaterializer = secretMaterializer,
        auditLogger = auditLogger,
        debugLogger = debugLogger,
        metrics = oagMetrics,
        tracer = tracer,
        rateLimiterRegistry = rateLimiterRegistry,
        dataBudgetTracker = DataBudgetTracker(),
        tokenBudgetTracker = TokenBudgetTracker(),
        sessionRequestTracker = sessionRequestTracker,
        circuitBreakerRegistry = circuitBreakerRegistry,
        connectionPool = connectionPool,
        hostCertificateCache = hostCertificateCache,
        caBundle = caBundle,
        webhookCallback = webhookCallback,
        detectorRegistry = detectorRegistry
    )

    return ProxyComponents(
        debugLogger = debugLogger,
        auditLogger = auditLogger,
        otelLogger = otelLogger,
        tracer = tracer,
        policyService = policyService,
        webhookSender = webhookSender,
        webhookScope = webhookScope,
        webhookCallback = webhookCallback,
        oagMetrics = oagMetrics,
        circuitBreakerRegistry = circuitBreakerRegistry,
        rateLimiterRegistry = rateLimiterRegistry,
        connectionPool = connectionPool,
        caBundle = caBundle,
        hostCertificateCache = hostCertificateCache,
        sslServerSocketFactory = sslServerSocketFactory,
        secretMaterializer = secretMaterializer,
        sessionRequestTracker = sessionRequestTracker,
        detectorRegistry = detectorRegistry,
        handler = handler,
        handlerConfig = handlerConfig
    )
}

internal fun buildSecretMaterializer(config: ProxyConfig): SecretMaterializer {
    val provider = buildSecretProvider(
        type = config.secret.provider,
        config = SecretProviderConfig(
            envPrefix = config.secret.envPrefix,
            fileDir = config.secret.fileDir,
            oauth2TokenUrl = config.oauth2.tokenUrl,
            oauth2ClientId = config.oauth2.clientId,
            oauth2ClientSecret = config.oauth2.clientSecret,
            oauth2Scope = config.oauth2.scope
        )
    )
    return SecretMaterializer(provider)
}

private const val PEM_LINE_WIDTH = 64

internal fun buildProxyAuditOutputStream(config: ProxyConfig, onError: (String) -> Unit): OutputStream =
    buildAuditOutputStream(
        logPath = config.log.path,
        maxSizeMb = config.log.maxSizeMb,
        maxFiles = config.log.maxFiles,
        compress = config.log.compress,
        rotationInterval = config.log.rotationInterval,
        onError = onError
    )

internal fun buildWebhookSender(config: ProxyConfig, debugLogger: DebugLogger): WebhookSender? =
    if (config.webhook.url != null) {
        WebhookSender(
            config = WebhookConfig(
                url = config.webhook.url,
                events = config.webhook.events,
                timeoutMs = config.webhook.timeoutMs,
                signingSecret = config.webhook.signingSecret
            ),
            debugLogger = debugLogger
        )
    } else {
        null
    }

internal fun buildCircuitBreakerRegistry(
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    webhookCallback: WebhookCallback?
): CircuitBreakerRegistry =
    CircuitBreakerRegistry(
        failureThreshold = config.cb.threshold,
        resetTimeoutMs = config.cb.resetMs,
        halfOpenSuccessThreshold = config.cb.halfOpenProbes,
        onStateChange = { host, from, to ->
            debugLogger.log("circuit breaker host=$host $from -> $to")
            auditLogger.logCircuitBreakerEvent(
                AuditCircuitBreakerEvent(
                    oagVersion = config.oagVersion,
                    host = host,
                    previousState = from.label(),
                    newState = to.label(),
                    agentId = config.identity.agentId,
                    sessionId = config.identity.sessionId
                )
            )
            if (to == CircuitState.OPEN) {
                webhookCallback?.send(
                    WebhookPayloadKeys.EVENT_CIRCUIT_OPEN,
                    webhookData(
                        WebhookPayloadKeys.DATA_HOST to host,
                        WebhookPayloadKeys.DATA_PREVIOUS_STATE to from.label(),
                        WebhookPayloadKeys.DATA_NEW_STATE to to.label()
                    )
                )
            }
        }
    )

internal fun buildCaBundle(config: ProxyConfig, debugLogger: DebugLogger): CaBundle? {
    if (!config.tls.inspect) return null
    val bundle = generateCaBundle()
    config.tls.caCertPath?.let { certPath ->
        val certPem = buildString {
            append(CryptoConstants.PEM_BEGIN_CERTIFICATE).append('\n')
            append(Base64.getMimeEncoder(PEM_LINE_WIDTH, "\n".toByteArray()).encodeToString(bundle.certificate.encoded))
            append('\n').append(CryptoConstants.PEM_END_CERTIFICATE).append('\n')
        }
        val certFile = Path.of(certPath)
        certFile.parent?.let { Files.createDirectories(it) }
        Files.writeString(certFile, certPem)
        debugLogger.log("tls ca certificate written to $certPath")
    }
    return bundle
}

internal fun buildHandlerConfig(config: ProxyConfig) = HandlerConfig(
    security = SecurityConfig(
        agentSigningSecret = config.identity.agentSigningSecret,
        requireSignedHeaders = config.identity.requireSignedHeaders
    ),
    network = NetworkConfig(
        blockIpLiterals = config.network.blockIpLiterals,
        blockPrivateResolvedIps = config.network.blockPrivateResolvedIps,
        enforceRedirectPolicy = config.network.enforceRedirectPolicy,
        connectTimeoutMs = config.network.connectTimeoutMs,
        readTimeoutMs = config.network.readTimeoutMs
    ),
    requestId = RequestIdConfig(
        injectRequestId = config.injectRequestId,
        requestIdHeader = config.requestIdHeader
    ),
    params = HandlerParams(
        agentId = config.identity.agentId,
        sessionId = config.identity.sessionId,
        dryRun = config.dryRun,
        oagVersion = config.oagVersion
    ),
    velocitySpikeThreshold = config.velocitySpikeThreshold
)

internal fun buildWebhookCallback(
    webhookSender: WebhookSender?,
    webhookScope: CoroutineScope?
): WebhookCallback? = webhookSender?.let { ws ->
    val scope = requireNotNull(webhookScope) { "webhookScope required when webhook is configured" }
    WebhookCallback { eventType, data ->
        scope.launch {
            ws.send(WebhookPayload(eventType = eventType, data = data))
        }
    }
}

internal fun buildConnectionPool(config: ProxyConfig): ConnectionPool? =
    if (config.pool.maxIdle > 0) {
        ConnectionPool(maxIdlePerHost = config.pool.maxIdle, idleTimeoutMs = config.pool.idleTimeoutMs)
    } else {
        null
    }

internal fun buildMtlsSslFactory(config: ProxyConfig): SSLServerSocketFactory? =
    config.tls.mtlsKeystorePath?.let { keystorePath ->
        buildMtlsServerSocketFactory(
            keystorePath = keystorePath,
            keystorePassword = config.tls.mtlsKeystorePassword,
            caCertPath = requireNotNull(config.tls.mtlsCaCertPath) { "mtlsCaCertPath must be set when mtlsKeystorePath is set" }
        )
    }

