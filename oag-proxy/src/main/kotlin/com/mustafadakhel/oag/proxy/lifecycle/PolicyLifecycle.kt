package com.mustafadakhel.oag.proxy.lifecycle

import com.mustafadakhel.oag.BackgroundTaskRegistry
import com.mustafadakhel.oag.MS_PER_SECOND
import com.mustafadakhel.oag.audit.AuditPolicyFetchEvent
import com.mustafadakhel.oag.audit.AuditPolicyReloadEvent
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.policy.lifecycle.PolicyFetchConfig
import com.mustafadakhel.oag.policy.lifecycle.PolicyFetcher
import com.mustafadakhel.oag.policy.lifecycle.PolicyFileWatcher
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.proxy.reliability.ExponentialBackoff
import com.mustafadakhel.oag.proxy.ProxyConfig
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.proxy.ReloadCallbackResult
import com.mustafadakhel.oag.proxy.ReloadTrigger
import com.mustafadakhel.oag.pipeline.WebhookCallback
import com.mustafadakhel.oag.pipeline.webhookData
import com.mustafadakhel.oag.pipeline.WebhookPayloadKeys
import com.mustafadakhel.oag.telemetry.DebugLogger

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

import java.nio.file.Path

internal fun buildPolicyWatcher(
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    policyService: PolicyService,
    rateLimiterRegistry: RateLimiterRegistry
): PolicyFileWatcher =
    PolicyFileWatcher(
        policyPath = Path.of(config.policy.path),
        policyService = policyService,
        onReload = { result ->
            debugLogger.log("policy reloaded changed=${result.changed} hash=${result.newHash}")
            if (result.changed) {
                reconfigureRateLimiters(policyService, rateLimiterRegistry)
            }
            auditLogger.logPolicyReloadEvent(buildReloadAuditEvent(
                config, result.previousHash, result.newHash, result.changed, success = true,
                trigger = ReloadTrigger.FILE_WATCHER.label()
            ))
        },
        onError = { error ->
            debugLogger.log("policy reload failed: ${error.message}")
            auditLogger.logPolicyReloadEvent(buildReloadAuditEvent(
                config, policyService.currentHash, newHash = null, changed = false, success = false,
                trigger = ReloadTrigger.FILE_WATCHER.label(), errorMessage = error.message
            ))
        }
    )

internal fun buildReloadCallback(
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    webhookCallback: WebhookCallback?,
    policyService: PolicyService,
    rateLimiterRegistry: RateLimiterRegistry,
    integrityCheckerProvider: () -> IntegrityChecker?
): (ReloadTrigger) -> ReloadCallbackResult = { trigger ->
    try {
        val result = policyService.reload()
        debugLogger.log("reload trigger=${trigger.label()} changed=${result.changed} hash=${result.newHash}")
        onReloadSuccess(result, policyService, rateLimiterRegistry, integrityCheckerProvider)
        auditReload(auditLogger, config, result.previousHash, result.newHash, result.changed, trigger)
        ReloadCallbackResult(
            success = true,
            changed = result.changed,
            newHash = result.newHash
        )
    } catch (e: Exception) {
        debugLogger.log("reload trigger=${trigger.label()} failed: ${e.message}")
        auditReloadFailure(auditLogger, config, policyService.currentHash, trigger, e.message)
        notifyReloadFailure(webhookCallback, trigger, e.message)
        ReloadCallbackResult(
            success = false,
            changed = false,
            errorMessage = e.message
        )
    }
}

private fun onReloadSuccess(
    result: PolicyService.ReloadResult,
    policyService: PolicyService,
    rateLimiterRegistry: RateLimiterRegistry,
    integrityCheckerProvider: () -> IntegrityChecker?
) {
    if (!result.changed) return
    reconfigureRateLimiters(policyService, rateLimiterRegistry)
    integrityCheckerProvider()?.updateExpectedPolicyHash(result.newHash)
}

private fun auditReload(
    auditLogger: AuditLogger,
    config: ProxyConfig,
    previousHash: String,
    newHash: String,
    changed: Boolean,
    trigger: ReloadTrigger
) {
    auditLogger.logPolicyReloadEvent(buildReloadAuditEvent(
        config, previousHash, newHash, changed,
        success = true, trigger = trigger.label()
    ))
}

private fun auditReloadFailure(
    auditLogger: AuditLogger,
    config: ProxyConfig,
    currentHash: String,
    trigger: ReloadTrigger,
    errorMessage: String?
) {
    auditLogger.logPolicyReloadEvent(buildReloadAuditEvent(
        config, currentHash, newHash = null, changed = false,
        success = false, trigger = trigger.label(), errorMessage = errorMessage
    ))
}

private fun notifyReloadFailure(
    webhookCallback: WebhookCallback?,
    trigger: ReloadTrigger,
    errorMessage: String?
) {
    webhookCallback?.send(
        WebhookPayloadKeys.EVENT_RELOAD_FAILED,
        webhookData(
            WebhookPayloadKeys.DATA_TRIGGER to trigger.label(),
            WebhookPayloadKeys.DATA_ERROR to errorMessage
        )
    )
}

internal fun launchPolicyFetcher(
    scope: CoroutineScope,
    registry: BackgroundTaskRegistry,
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    reloadCallback: (ReloadTrigger) -> ReloadCallbackResult
) {
    val policyConfig = config.policy
    val policyUrl = requireNotNull(policyConfig.url) { "policyUrl required for remote fetch" }
    val fetcher = PolicyFetcher(
        config = PolicyFetchConfig(
            url = policyUrl,
            intervalSeconds = policyConfig.fetchIntervalS,
            cachePath = Path.of(policyConfig.path),
            timeoutMs = ProxyDefaults.POLICY_FETCH_TIMEOUT_MS
        ),
        debugLog = debugLogger::log
    )
    val backoff = ExponentialBackoff(baseDelayMs = policyConfig.fetchIntervalS * MS_PER_SECOND)
    val handle = registry.register(TASK_POLICY_FETCHER)
    handle.running = true
    scope.launch(Dispatchers.IO) {
        try {
            while (isActive) {
                try {
                    val result = fetcher.fetch()
                    backoff.recordSuccess()
                    handle.recordSuccess(System.currentTimeMillis())
                    auditLogger.logPolicyFetchEvent(
                        AuditPolicyFetchEvent(
                            oagVersion = config.oagVersion,
                            sourceUrl = policyUrl,
                            success = true,
                            changed = result.changed,
                            contentHash = result.contentHash,
                            agentId = config.identity.agentId,
                            sessionId = config.identity.sessionId
                        )
                    )
                    if (result.changed) {
                        reloadCallback(ReloadTrigger.POLICY_FETCH)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    backoff.recordFailure()
                    handle.recordError(System.currentTimeMillis(), e.message)
                    debugLogger.log("policy fetch failed: ${e.message}")
                    auditLogger.logPolicyFetchEvent(
                        AuditPolicyFetchEvent(
                            oagVersion = config.oagVersion,
                            sourceUrl = policyUrl,
                            success = false,
                            errorMessage = e.message,
                            agentId = config.identity.agentId,
                            sessionId = config.identity.sessionId
                        )
                    )
                }
                delay(backoff.nextDelayMs())
            }
        } finally {
            handle.running = false
        }
    }
    debugLogger.log("policy fetcher started url=$policyUrl interval=${policyConfig.fetchIntervalS}s")
}

private fun buildReloadAuditEvent(
    config: ProxyConfig,
    previousHash: String,
    newHash: String?,
    changed: Boolean,
    success: Boolean,
    trigger: String,
    errorMessage: String? = null
) = AuditPolicyReloadEvent(
    oagVersion = config.oagVersion,
    previousPolicyHash = previousHash,
    newPolicyHash = newHash,
    changed = changed,
    success = success,
    errorMessage = errorMessage,
    trigger = trigger,
    agentId = config.identity.agentId,
    sessionId = config.identity.sessionId
)

internal fun reconfigureRateLimiters(policyService: PolicyService, rateLimiterRegistry: RateLimiterRegistry) {
    val configs = policyService.rateLimitConfigs()
    rateLimiterRegistry.replaceAll(configs)
}
