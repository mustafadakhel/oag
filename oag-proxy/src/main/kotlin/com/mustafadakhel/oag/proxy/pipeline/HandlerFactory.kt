package com.mustafadakhel.oag.proxy.pipeline

import com.mustafadakhel.oag.pipeline.AuditEmitter
import com.mustafadakhel.oag.pipeline.ContextFactory
import com.mustafadakhel.oag.pipeline.buildContextFactory
import com.mustafadakhel.oag.pipeline.buildRequestExceptionHandler
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.Pipeline
import com.mustafadakhel.oag.pipeline.RequestPath
import com.mustafadakhel.oag.inspection.injection.CharCodeTokenizer
import com.mustafadakhel.oag.inspection.injection.CombinedInjectionClassifier
import com.mustafadakhel.oag.inspection.injection.DjlHuggingFaceTokenizer
import com.mustafadakhel.oag.inspection.injection.HeuristicInjectionClassifier
import com.mustafadakhel.oag.inspection.injection.InjectionClassifier
import com.mustafadakhel.oag.inspection.injection.MlTriggerMode
import com.mustafadakhel.oag.inspection.injection.OnnxInjectionClassifier
import com.mustafadakhel.oag.inspection.injection.Tokenizer
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.pipeline.RequestRelay
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.pipeline.buildPipelinePath
import com.mustafadakhel.oag.pipeline.buildScopedPath
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.proxy.ProxyHandler
import com.mustafadakhel.oag.proxy.relay.HttpRelayHandler
import com.mustafadakhel.oag.proxy.relay.MitmTrafficLoop
import com.mustafadakhel.oag.proxy.relay.buildConnectRelay
import com.mustafadakhel.oag.proxy.relay.buildMitmRelay
import com.mustafadakhel.oag.proxy.relay.buildMitmTunnelEstablisher
import com.mustafadakhel.oag.proxy.relay.buildTunnelRelay
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.proxy.http.parseHttpRequest
import com.mustafadakhel.oag.http.parseAbsoluteTarget
import com.mustafadakhel.oag.http.parseAuthorityTarget
import com.mustafadakhel.oag.pipeline.buildHttpPipeline
import com.mustafadakhel.oag.pipeline.buildConnectPipeline
import com.mustafadakhel.oag.pipeline.buildMitmPrePolicyPipeline
import com.mustafadakhel.oag.pipeline.buildMitmPipeline
import com.mustafadakhel.oag.pipeline.relay.ResponseRelayer
import com.mustafadakhel.oag.pipeline.relay.UpstreamConnector
import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.ConnectionPool
import com.mustafadakhel.oag.proxy.tls.CaBundle
import com.mustafadakhel.oag.proxy.tls.HostCertificateCache
import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.pipeline.ExternalTopicClassifierClient
import com.mustafadakhel.oag.pipeline.TopicClassifierClient
import com.mustafadakhel.oag.pipeline.inspection.ExternalJudgeClient
import com.mustafadakhel.oag.pipeline.inspection.JudgeCallContext
import com.mustafadakhel.oag.pipeline.inspection.JudgeInvoker
import com.mustafadakhel.oag.pipeline.inspection.JudgeRequest
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.telemetry.OagMetrics
import com.mustafadakhel.oag.telemetry.OagTracer

import java.net.InetAddress
import java.time.Clock

internal fun buildProxyHandler(
    httpPath: RequestPath,
    connectPath: RequestPath,
    contextFactory: ContextFactory,
    parseErrorHandler: ParseErrorHandler,
    debugLogger: DebugLogger,
    metrics: OagMetrics?,
    clock: Clock
): ProxyHandler {
    return ProxyHandler { clientInput, clientOutput, clientSocket, connectionIdentity ->
        metrics?.incrementActiveConnections()
        val startMs = clock.millis()
        try {
            val request = parseHttpRequest(clientInput)
            val isConnect = request.method.equals(HttpConstants.METHOD_CONNECT, ignoreCase = true)
            val target = if (isConnect) parseAuthorityTarget(request.target) else parseAbsoluteTarget(request.target)
            debugLogger.log {
                if (isConnect) "connect ${target.host}:${target.port}"
                else "http ${request.method} ${target.scheme}://${target.host}:${target.port}${target.path}"
            }
            val context = contextFactory.build(
                target, request, CountingOutputStream(clientOutput),
                connectionIdentity, clientInput, if (isConnect) clientSocket else null
            )
            val path = if (isConnect) connectPath else httpPath
            path.process(context)
        } catch (e: Exception) {
            parseErrorHandler.handleBadRequest(clientOutput, e, connectionIdentity?.actorId)
        } finally {
            metrics?.decrementActiveConnections()
            metrics?.recordDuration(clock.millis() - startMs)
        }
    }
}

/**
 * Convenience factory that composes the full handler from domain-level params.
 * Wires pipelines, relays, paths, and supporting factories internally.
 */
internal fun buildFullProxyHandler(
    config: HandlerConfig,
    policyService: PolicyService,
    secretMaterializer: SecretMaterializer,
    auditLogger: AuditLogger,
    debugLogger: DebugLogger = DebugLogger.NOOP,
    metrics: OagMetrics? = null,
    tracer: OagTracer? = null,
    clock: Clock = Clock.systemUTC(),
    hostResolver: HostResolver = HostResolver { host -> InetAddress.getAllByName(host).toList() },
    connectionPool: ConnectionPool? = null,
    circuitBreakerRegistry: CircuitBreakerRegistry? = null,
    rateLimiterRegistry: RateLimiterRegistry,
    dataBudgetTracker: DataBudgetTracker,
    tokenBudgetTracker: TokenBudgetTracker,
    sessionRequestTracker: SessionRequestTracker? = null,
    hostCertificateCache: HostCertificateCache? = null,
    caBundle: CaBundle? = null,
    webhookCallback: WebhookCallback? = null,
    detectorRegistry: DetectorRegistry = DetectorRegistry.empty()
): ProxyHandler {
    val mlClassifier: InjectionClassifier? = policyService.current.defaults?.mlClassifier?.let { mlConfig ->
        val modelPath = mlConfig.modelPath
        if (mlConfig.enabled != true || modelPath == null) return@let null
        val tokenizerPath = mlConfig.tokenizerPath
        val tokenizer: Tokenizer = if (tokenizerPath != null && DjlHuggingFaceTokenizer.isAvailable()) {
            DjlHuggingFaceTokenizer.createOrNull(tokenizerPath, onError = debugLogger::log)
                ?: run {
                    debugLogger.log("DJL tokenizer failed to load from $tokenizerPath, falling back to char-code tokenization")
                    CharCodeTokenizer()
                }
        } else {
            if (tokenizerPath != null) {
                debugLogger.log("ml_classifier.tokenizer_path is set but DJL is not on classpath; using char-code tokenization")
            }
            CharCodeTokenizer()
        }
        val onnx = OnnxInjectionClassifier.createOrNull(
            modelPath = modelPath,
            maxLength = mlConfig.maxLength ?: OnnxInjectionClassifier.DEFAULT_MAX_LENGTH,
            confidenceThreshold = mlConfig.confidenceThreshold ?: OnnxInjectionClassifier.DEFAULT_CONFIDENCE_THRESHOLD,
            tokenizer = tokenizer,
            onError = debugLogger::log
        ) ?: return@let null
        val triggerMode = when (mlConfig.triggerMode) {
            "uncertain_only" -> MlTriggerMode.UNCERTAIN_ONLY
            else -> MlTriggerMode.ALWAYS
        }
        CombinedInjectionClassifier(
            heuristic = HeuristicInjectionClassifier(),
            ml = onnx,
            mlTriggerMode = triggerMode,
            uncertainLow = mlConfig.uncertainLow ?: CombinedInjectionClassifier.DEFAULT_UNCERTAIN_LOW,
            uncertainHigh = mlConfig.uncertainHigh ?: CombinedInjectionClassifier.DEFAULT_UNCERTAIN_HIGH,
            onError = debugLogger::log
        )
    }

    val topicClassifierClient: TopicClassifierClient? = policyService.current.defaults?.topicClassification?.let { topicConfig ->
        val endpointUrl = topicConfig.endpointUrl
        if (topicConfig.enabled != true || endpointUrl == null) return@let null
        runCatching {
            ExternalTopicClassifierClient(
                client = SafeOutboundClient(connectTimeoutMs = (topicConfig.endpointTimeoutMs ?: DEFAULT_TOPIC_TIMEOUT_MS).toLong()),
                endpointUrl = endpointUrl,
                timeoutMs = (topicConfig.endpointTimeoutMs ?: DEFAULT_TOPIC_TIMEOUT_MS).toLong(),
                signingSecret = topicConfig.signingSecret,
                maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES
            )
        }.onFailure { e ->
            debugLogger.log("topic classification client construction failed: ${e.message}")
        }.getOrNull()
    }

    val judgeInvoker: JudgeInvoker? = policyService.current.defaults?.externalJudge?.let { judgeConfig ->
        val endpointUrl = judgeConfig.endpointUrl
        if (judgeConfig.enabled != true || endpointUrl == null) return@let null
        val client = runCatching {
            ExternalJudgeClient(
                client = SafeOutboundClient(connectTimeoutMs = (judgeConfig.timeoutMs ?: DEFAULT_JUDGE_TIMEOUT_MS).toLong()),
                endpointUrl = endpointUrl,
                timeoutMs = (judgeConfig.timeoutMs ?: DEFAULT_JUDGE_TIMEOUT_MS).toLong(),
                signingSecret = judgeConfig.signingSecret,
                maxResponseBytes = judgeConfig.maxResponseBytes ?: DEFAULT_MAX_RESPONSE_BYTES
            )
        }.onFailure { e ->
            debugLogger.log("external judge client construction failed: ${e.message}")
        }.getOrNull() ?: return@let null
        JudgeInvoker { ctx -> client.invoke(ctx.toJudgeRequest()) }
    }

    val httpPipeline = buildHttpPipeline(
        config = config,
        policyService = policyService,
        hostResolver = hostResolver,
        rateLimiterRegistry = rateLimiterRegistry,
        sessionRequestTracker = sessionRequestTracker,
        dataBudgetTracker = dataBudgetTracker,
        tokenBudgetTracker = tokenBudgetTracker,
        secretMaterializer = secretMaterializer,
        circuitBreakerRegistry = circuitBreakerRegistry,
        detectorRegistry = detectorRegistry,
        mlClassifier = mlClassifier,
        topicClassifierClient = topicClassifierClient,
        judgeInvoker = judgeInvoker
    )
    val connectPipeline = buildConnectPipeline(
        config = config,
        policyService = policyService,
        hostResolver = hostResolver,
        rateLimiterRegistry = rateLimiterRegistry,
        sessionRequestTracker = sessionRequestTracker,
        circuitBreakerRegistry = circuitBreakerRegistry
    )

    val responseRelayer = ResponseRelayer(
        policyService = policyService,
        hostResolver = hostResolver,
        networkConfig = config.network,
        dryRun = config.params.dryRun,
        detectorRegistry = detectorRegistry,
        onError = debugLogger::log
    )
    val upstreamConnector = UpstreamConnector(
        connectTimeoutMs = config.network.connectTimeoutMs,
        readTimeoutMs = config.network.readTimeoutMs,
        debugLogger = debugLogger
    )

    val httpRelay: RequestRelay = HttpRelayHandler(
        policyService = policyService,
        responseRelayer = responseRelayer,
        debugLogger = debugLogger,
        upstreamConnector = upstreamConnector,
        connectionPool = connectionPool,
        circuitBreakerRegistry = circuitBreakerRegistry,
        tokenBudgetTracker = tokenBudgetTracker,
        detectorRegistry = detectorRegistry,
        metrics = metrics
    )
    val tunnelRelay = buildTunnelRelay(
        upstreamConnector = upstreamConnector,
        circuitBreakerRegistry = circuitBreakerRegistry,
        debugLogger = debugLogger
    )
    val mitmPrePolicyPipeline = buildMitmPrePolicyPipeline(
        config = config,
        policyService = policyService
    )
    val mitmPipeline = buildMitmPipeline(
        policyService = policyService,
        rateLimiterRegistry = rateLimiterRegistry,
        sessionRequestTracker = sessionRequestTracker,
        dataBudgetTracker = dataBudgetTracker,
        tokenBudgetTracker = tokenBudgetTracker,
        secretMaterializer = secretMaterializer,
        circuitBreakerRegistry = circuitBreakerRegistry,
        detectorRegistry = detectorRegistry,
        mlClassifier = mlClassifier,
        topicClassifierClient = topicClassifierClient,
        judgeInvoker = judgeInvoker
    )
    val mitmRelay: RequestRelay? = if (hostCertificateCache != null && caBundle != null) {
        buildMitmRelay(
            buildMitmTunnelEstablisher(upstreamConnector, circuitBreakerRegistry, hostCertificateCache, caBundle),
            MitmTrafficLoop(mitmPrePolicyPipeline, mitmPipeline, policyService, responseRelayer, tokenBudgetTracker, circuitBreakerRegistry, webhookCallback)
        )
    } else null
    val connectRelay = buildConnectRelay(tunnelRelay, mitmRelay)

    val exceptionHandler = buildRequestExceptionHandler(circuitBreakerRegistry, webhookCallback)
    val httpPath = buildScopedPath(buildPipelinePath(httpPipeline, httpRelay), exceptionHandler)
    val connectPath = buildScopedPath(buildPipelinePath(connectPipeline, connectRelay), exceptionHandler)

    val auditEmitter = AuditEmitter { event ->
        metrics?.recordRequest(
            action = event.decision.action,
            reasonCode = event.decision.reasonCode,
            ruleId = event.decision.ruleId,
            tags = event.tags
        )
        val reasonCode = event.decision.reasonCode
        if (reasonCode == ReasonCode.RATE_LIMITED.label() || reasonCode == ReasonCode.VELOCITY_SPIKE_DETECTED.label()) {
            metrics?.recordRateLimited()
        }
        event.phaseTimings?.forEach { (key, ms) ->
            metrics?.recordPhaseDuration(key.removeSuffix("_ms"), ms)
        }
        if (event.dryRunOverride == true) metrics?.recordDryRunOverride()
        auditLogger.log(event)
    }

    val contextFactory = buildContextFactory(config, policyService::currentHash, tracer, debugLogger, auditEmitter)
    val parseErrorHandler = buildParseErrorHandler(config, policyService::currentHash, auditLogger)

    return buildProxyHandler(httpPath, connectPath, contextFactory, parseErrorHandler, debugLogger, metrics, clock)
}

private const val DEFAULT_TOPIC_TIMEOUT_MS = 5_000
private const val DEFAULT_JUDGE_TIMEOUT_MS = 5_000
private const val DEFAULT_MAX_RESPONSE_BYTES = 65_536

private fun JudgeCallContext.toJudgeRequest() = JudgeRequest(
    requestBody = requestBody,
    host = host,
    path = path,
    method = method,
    injectionScore = injectionScore
)
