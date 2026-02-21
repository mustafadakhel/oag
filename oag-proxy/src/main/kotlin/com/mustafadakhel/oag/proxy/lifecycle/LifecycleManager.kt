package com.mustafadakhel.oag.proxy.lifecycle

import com.mustafadakhel.oag.BackgroundTaskRegistry
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.MS_PER_SECOND
import com.mustafadakhel.oag.audit.AuditAdminAccessEvent
import com.mustafadakhel.oag.audit.AuditIntegrityCheckEvent
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.lifecycle.PolicyFileWatcher
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.proxy.ProxyComponents
import com.mustafadakhel.oag.proxy.ProxyConfig
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.proxy.ProxyServer
import com.mustafadakhel.oag.proxy.ReloadCallbackResult
import com.mustafadakhel.oag.proxy.ReloadTrigger
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.proxy.admin.AdminAccessCallback
import com.mustafadakhel.oag.proxy.admin.AdminServer
import com.mustafadakhel.oag.proxy.admin.AdminServerDeps
import com.mustafadakhel.oag.proxy.admin.PolicyInfo
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.pipeline.webhookData
import com.mustafadakhel.oag.enforcement.ConnectionPool
import com.mustafadakhel.oag.pipeline.WebhookPayloadKeys
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.telemetry.OagMetrics
import com.mustafadakhel.oag.telemetry.OagTracer
import com.mustafadakhel.oag.telemetry.OtelAuditLogger

import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

import java.time.Instant

internal fun launchPoolEvictor(
    scope: CoroutineScope,
    registry: BackgroundTaskRegistry,
    config: ProxyConfig,
    connectionPool: ConnectionPool,
    debugLogger: DebugLogger,
    metrics: OagMetrics? = null
) {
    debugLogger.log("connection pooling enabled max_idle=${config.pool.maxIdle} idle_timeout_ms=${config.pool.idleTimeoutMs}")
    launchTrackedPeriodic(scope, registry, TASK_POOL_EVICTOR, config.pool.idleTimeoutMs / 2) {
        val evicted = connectionPool.evictExpired()
        repeat(evicted) { metrics?.recordPoolEviction() }
    }
}

internal fun launchAdminServer(
    scope: CoroutineScope,
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    webhookCallback: WebhookCallback?,
    server: ProxyServer,
    policyService: PolicyService,
    oagMetrics: OagMetrics,
    connectionPool: ConnectionPool?,
    reloadCallback: (ReloadTrigger) -> ReloadCallbackResult,
    taskRegistry: BackgroundTaskRegistry? = null,
    pluginProviderCount: Int = 0
): AdminServer {
    val startedAt = Instant.now().toString()
    val admin = AdminServer(
        listenPort = requireNotNull(config.admin.port) { "admin port required to start admin server" },
        deps = AdminServerDeps(
            metrics = oagMetrics,
            oagVersion = config.oagVersion,
            policyHashProvider = { policyService.currentHash },
            drainingProvider = { server.isDraining },
            reloadCallback = { reloadCallback(ReloadTrigger.ADMIN_ENDPOINT) },
            policyInfoProvider = {
                val doc = policyService.current
                PolicyInfo(
                    hash = policyService.currentHash,
                    allowRuleCount = doc.allow?.size ?: 0,
                    denyRuleCount = doc.deny?.size ?: 0,
                    loadedAt = policyService.currentLoadedAt
                )
            },
            policyHistoryProvider = { policyService.policyHistory },
            poolStatsProvider = { connectionPool?.stats() },
            taskSnapshotProvider = taskRegistry?.let { reg -> { reg.snapshot() } },
            reloadCooldownMs = config.admin.reloadCooldownMs,
            pluginProviderCount = pluginProviderCount
        ),
        adminAccessCallback = buildAdminAccessCallback(config, auditLogger, webhookCallback),
        allowedIps = config.admin.allowedIps,
        adminToken = config.admin.token
    )
    scope.launch(Dispatchers.IO) { admin.start() }
    debugLogger.log("admin server started on ${ProxyDefaults.ADMIN_LISTEN_HOST}:${config.admin.port}")
    return admin
}

internal fun launchIntegrityChecker(
    scope: CoroutineScope,
    registry: BackgroundTaskRegistry,
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    webhookCallback: WebhookCallback?,
    policyService: PolicyService
): IntegrityChecker {
    val configFingerprint = computeConfigFingerprint(config)
    val integrityChecker = IntegrityChecker(
        policyService = policyService,
        expectedPolicyHash = policyService.currentHash,
        initialConfigFingerprint = configFingerprint
    )
    launchTrackedPeriodic(
        scope, registry, TASK_INTEGRITY_CHECKER, config.integrityCheckIntervalS * MS_PER_SECOND
    ) {
        val currentFingerprint = computeConfigFingerprint(config)
        val result = integrityChecker.checkWithFingerprint(currentFingerprint)
        if (result.status != IntegrityStatus.PASS) {
            debugLogger.log("integrity check: ${result.status.label()}")
            webhookCallback?.send(
                WebhookPayloadKeys.EVENT_INTEGRITY_DRIFT,
                webhookData(
                    WebhookPayloadKeys.DATA_STATUS to result.status.label(),
                    WebhookPayloadKeys.DATA_POLICY_HASH_MATCH to result.policyHashMatch,
                    WebhookPayloadKeys.DATA_CONFIG_FINGERPRINT_MATCH to result.configFingerprintMatch
                )
            )
        }
        auditLogger.logIntegrityCheckEvent(
            AuditIntegrityCheckEvent(
                oagVersion = config.oagVersion,
                status = result.status.label(),
                policyHashMatch = result.policyHashMatch,
                configFingerprintMatch = result.configFingerprintMatch,
                agentId = config.identity.agentId,
                sessionId = config.identity.sessionId
            )
        )
    }
    debugLogger.log("integrity checker started interval=${config.integrityCheckIntervalS}s")
    return integrityChecker
}

internal class ShutdownResources(
    val webhookScope: CoroutineScope?,
    val adminServer: AdminServer?,
    val connectionPool: ConnectionPool?,
    val policyWatcher: PolicyFileWatcher?,
    val tracer: OagTracer?,
    val otelLogger: OtelAuditLogger?,
    val auditLogger: AuditLogger,
    val detectorRegistry: DetectorRegistry = DetectorRegistry.empty()
)

internal fun ShutdownResources(
    components: ProxyComponents,
    adminServer: AdminServer?,
    policyWatcher: PolicyFileWatcher?
) = ShutdownResources(
    webhookScope = components.webhookScope,
    adminServer = adminServer,
    connectionPool = components.connectionPool,
    policyWatcher = policyWatcher,
    tracer = components.tracer,
    otelLogger = components.otelLogger,
    auditLogger = components.auditLogger,
    detectorRegistry = components.detectorRegistry
)

internal fun installShutdownHook(
    server: ProxyServer,
    drainTimeoutMs: Long,
    debugLogger: DebugLogger,
    scope: CoroutineScope
) {
    Runtime.getRuntime().addShutdownHook(thread(start = false, name = "oag-shutdown") {
        debugLogger.log("shutdown signal received, draining connections")
        server.drain()
        val drained = server.awaitDrainBlocking(drainTimeoutMs)
        if (drained) {
            debugLogger.log("all connections drained")
        } else {
            debugLogger.log("drain timeout after ${drainTimeoutMs}ms, ${server.activeConnectionCount} connections still active")
        }
        scope.cancel("shutdown signal received")
    })
}

private fun buildAdminAccessCallback(
    config: ProxyConfig,
    auditLogger: AuditLogger,
    webhookCallback: WebhookCallback?
) = AdminAccessCallback { endpoint, sourceIp, action ->
    val allowed = action !is EnforcementAction.Deny
    auditLogger.logAdminAccessEvent(
        AuditAdminAccessEvent(
            oagVersion = config.oagVersion,
            endpoint = endpoint,
            sourceIp = sourceIp,
            allowed = allowed,
            agentId = config.identity.agentId,
            sessionId = config.identity.sessionId
        )
    )
    if (action is EnforcementAction.Deny) {
        webhookCallback?.send(
            WebhookPayloadKeys.EVENT_ADMIN_DENIED,
            webhookData(
                WebhookPayloadKeys.DATA_ENDPOINT to endpoint,
                WebhookPayloadKeys.DATA_SOURCE_IP to sourceIp
            )
        )
    }
}

internal fun ShutdownResources.closeAll(
    onError: (String) -> Unit = System.err::println
) {
    safeCloseAll(onError,
        { webhookScope?.cancel() },
        { adminServer?.close() },
        { connectionPool?.close() },
        { policyWatcher?.close() },
        { tracer?.close() },
        { otelLogger?.close() },
        { auditLogger.close() },
        { detectorRegistry.close(onError) }
    )
}

internal fun safeCloseAll(
    onError: (String) -> Unit,
    vararg operations: () -> Unit
) {
    for (operation in operations) {
        runCatching { operation() }.onFailure { e ->
            onError("${LOG_PREFIX}shutdown close failed: ${e.message}")
        }
    }
}

internal const val TASK_POOL_EVICTOR = "pool_evictor"
internal const val TASK_INTEGRITY_CHECKER = "integrity_checker"
internal const val TASK_POLICY_FETCHER = "policy_fetcher"
internal const val TASK_POLICY_WATCHER = "policy_watcher"
