package com.mustafadakhel.oag.proxy.admin

import com.mustafadakhel.oag.MS_PER_SECOND
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.HttpStatus

import java.io.OutputStream
import java.time.Clock
import java.util.concurrent.atomic.AtomicLong

internal class AdminRequestHandler(
    private val deps: AdminServerDeps,
    private val clock: Clock = Clock.systemUTC()
) {
    private val lastReloadMs = AtomicLong(0L)

    fun handle(method: String, path: String, output: OutputStream) {
        val route = AdminPath.entries.firstOrNull { it.path == path }
        when (route) {
            AdminPath.HEALTHZ -> {
                val draining = deps.drainingProvider()
                val statusCode = if (draining) HttpStatus.SERVICE_UNAVAILABLE.code else HttpStatus.OK.code
                respondJson(output, statusCode, buildHealthResponse(draining))
            }
            AdminPath.METRICS -> writeAdminResponse(
                output = output,
                statusCode = HttpStatus.OK.code,
                contentType = HttpConstants.PROMETHEUS_CONTENT_TYPE,
                body = deps.metrics.toPrometheusText()
            )
            AdminPath.RELOAD -> if (method == HttpConstants.METHOD_POST) {
                handleReload(output)
            } else {
                respondJson(output, HttpStatus.METHOD_NOT_ALLOWED.code, encodeAdminJson(
                    AdminErrorResponse(ok = false, error = "method not allowed, use POST")
                ))
            }
            AdminPath.POOL -> handlePoolStats(output)
            AdminPath.POLICY -> handlePolicyInfo(output)
            AdminPath.AUDIT -> handleAuditStats(output)
            AdminPath.TASKS -> handleTasks(output)
            null -> writeAdminResponse(
                output = output,
                statusCode = HttpStatus.NOT_FOUND.code,
                contentType = HttpConstants.TEXT_PLAIN,
                body = "not found\n"
            )
        }
    }

    private data class CooldownResult(val allowed: Boolean, val retryAfterS: Long = 0)

    private fun acquireReloadSlot(): CooldownResult {
        if (deps.reloadCooldownMs <= 0) return CooldownResult(allowed = true)
        val now = clock.millis()
        while (true) {
            val last = lastReloadMs.get()
            val elapsed = now - last
            if (elapsed < deps.reloadCooldownMs) {
                val retryAfterS = ((deps.reloadCooldownMs - elapsed + MS_PER_SECOND - 1) / MS_PER_SECOND)
                    .coerceAtLeast(1)
                return CooldownResult(allowed = false, retryAfterS = retryAfterS)
            }
            if (lastReloadMs.compareAndSet(last, now)) return CooldownResult(allowed = true)
        }
    }

    private fun handleReload(output: OutputStream) {
        val cb = deps.reloadCallback
        if (cb == null) {
            respondJson(output, HttpStatus.NOT_IMPLEMENTED.code, encodeAdminJson(
                AdminErrorResponse(ok = false, error = "reload not configured")
            ))
            return
        }
        val cooldown = acquireReloadSlot()
        if (!cooldown.allowed) {
            respondJson(output, HttpStatus.TOO_MANY_REQUESTS.code, encodeAdminJson(
                ReloadCooldownResponse(
                    ok = false,
                    error = "reload cooldown active, retry after ${cooldown.retryAfterS}s",
                    retryAfterS = cooldown.retryAfterS
                )
            ))
            return
        }
        val result = cb()
        if (result.success) {
            respondJson(output, HttpStatus.OK.code, encodeAdminJson(
                ReloadSuccessResponse(
                    ok = true,
                    changed = result.changed,
                    policyHash = result.newHash ?: deps.policyHashProvider()
                )
            ))
        } else {
            respondJson(output, HttpStatus.INTERNAL_SERVER_ERROR.code, encodeAdminJson(
                AdminErrorResponse(ok = false, error = result.errorMessage ?: "reload failed")
            ))
        }
    }

    private fun handlePoolStats(output: OutputStream) {
        val stats = deps.poolStatsProvider?.invoke()
        if (stats == null) {
            respondJson(output, HttpStatus.OK.code, encodeAdminJson(
                PoolDisabledResponse(ok = true, enabled = false)
            ))
            return
        }
        respondJson(output, HttpStatus.OK.code, encodeAdminJson(
            PoolStatsResponse(
                ok = true,
                enabled = true,
                idle = stats.currentIdle,
                hits = stats.hits,
                misses = stats.misses,
                evictions = stats.evictions
            )
        ))
    }

    private fun handlePolicyInfo(output: OutputStream) {
        val info = deps.policyInfoProvider?.invoke()
        if (info == null) {
            respondJson(output, HttpStatus.OK.code, encodeAdminJson(
                PolicyHashResponse(ok = true, policyHash = deps.policyHashProvider())
            ))
            return
        }
        val history = deps.policyHistoryProvider?.invoke()?.map { v ->
            PolicyVersionJson(hash = v.hash, timestamp = v.timestamp)
        }
        respondJson(output, HttpStatus.OK.code, encodeAdminJson(
            PolicyInfoResponse(
                ok = true,
                policyHash = info.hash,
                allowRuleCount = info.allowRuleCount,
                denyRuleCount = info.denyRuleCount,
                loadedAt = info.loadedAt,
                history = history
            )
        ))
    }

    private fun handleAuditStats(output: OutputStream) {
        val stats = deps.metrics.auditStats()
        respondJson(output, HttpStatus.OK.code, encodeAdminJson(
            AuditStatsResponse(ok = true, decisionCounts = stats)
        ))
    }

    private fun handleTasks(output: OutputStream) {
        val snapshots = deps.taskSnapshotProvider?.invoke()
        val taskJsons = snapshots?.map { task ->
            TaskSnapshotJson(
                name = task.name,
                running = task.running,
                successCount = task.successCount,
                errorCount = task.errorCount,
                lastSuccessMs = task.lastSuccessMs,
                lastErrorMs = task.lastErrorMs,
                lastError = task.lastError
            )
        } ?: emptyList()
        respondJson(output, HttpStatus.OK.code, encodeAdminJson(
            TasksResponse(ok = true, tasks = taskJsons)
        ))
    }

    private fun buildHealthResponse(draining: Boolean): String = encodeAdminJson(
        HealthResponse(
            status = if (draining) STATUS_DRAINING else STATUS_OK,
            version = deps.oagVersion,
            policyHash = deps.policyHashProvider(),
            pluginProviders = deps.pluginProviderCount.takeIf { it > 0 }
        )
    )

    private companion object {
        private const val STATUS_OK = "ok"
        private const val STATUS_DRAINING = "draining"
    }
}

private fun respondJson(
    output: OutputStream,
    statusCode: Int,
    body: String
) = writeAdminResponse(
    output = output,
    statusCode = statusCode,
    contentType = HttpConstants.APPLICATION_JSON,
    body = body
)
