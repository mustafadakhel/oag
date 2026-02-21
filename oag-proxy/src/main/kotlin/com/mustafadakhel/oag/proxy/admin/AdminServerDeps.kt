package com.mustafadakhel.oag.proxy.admin

import com.mustafadakhel.oag.TaskSnapshot
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.policy.lifecycle.PolicyVersion
import com.mustafadakhel.oag.proxy.ProxyDefaults
import com.mustafadakhel.oag.proxy.ReloadCallbackResult
import com.mustafadakhel.oag.enforcement.PoolStats
import com.mustafadakhel.oag.telemetry.OagMetrics

internal class AdminServerDeps(
    val metrics: OagMetrics,
    val oagVersion: String,
    val policyHashProvider: () -> String,
    val drainingProvider: () -> Boolean = { false },
    val reloadCallback: (() -> ReloadCallbackResult)? = null,
    val policyInfoProvider: (() -> PolicyInfo)? = null,
    val policyHistoryProvider: (() -> List<PolicyVersion>)? = null,
    val poolStatsProvider: (() -> PoolStats?)? = null,
    val taskSnapshotProvider: (() -> List<TaskSnapshot>)? = null,
    val reloadCooldownMs: Long = ProxyDefaults.ADMIN_RELOAD_COOLDOWN_MS.toLong(),
    val pluginProviderCount: Int = 0
)

internal fun interface AdminAccessCallback {
    fun onAccess(endpoint: String, sourceIp: String, action: EnforcementAction)
}
