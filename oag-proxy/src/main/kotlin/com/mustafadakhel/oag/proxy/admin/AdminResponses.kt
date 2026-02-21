package com.mustafadakhel.oag.proxy.admin

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal val adminJson = Json {
    encodeDefaults = true
    explicitNulls = false
}

@Serializable
internal data class HealthResponse(
    val status: String,
    val version: String,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("plugin_providers") val pluginProviders: Int? = null
)

@Serializable
internal data class AdminErrorResponse(
    val ok: Boolean,
    val error: String
)

@Serializable
internal data class ReloadCooldownResponse(
    val ok: Boolean,
    val error: String,
    @SerialName("retry_after_s") val retryAfterS: Long
)

@Serializable
internal data class ReloadSuccessResponse(
    val ok: Boolean,
    val changed: Boolean,
    @SerialName("policy_hash") val policyHash: String
)

@Serializable
internal data class PoolDisabledResponse(
    val ok: Boolean,
    val enabled: Boolean
)

@Serializable
internal data class PoolStatsResponse(
    val ok: Boolean,
    val enabled: Boolean,
    val idle: Int,
    val hits: Long,
    val misses: Long,
    val evictions: Long
)

@Serializable
internal data class PolicyHashResponse(
    val ok: Boolean,
    @SerialName("policy_hash") val policyHash: String
)

@Serializable
internal data class PolicyVersionJson(
    val hash: String,
    val timestamp: String
)

@Serializable
internal data class PolicyInfoResponse(
    val ok: Boolean,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("allow_rule_count") val allowRuleCount: Int,
    @SerialName("deny_rule_count") val denyRuleCount: Int,
    @SerialName("loaded_at") val loadedAt: String,
    val history: List<PolicyVersionJson>? = null
)

@Serializable
internal data class AuditStatsResponse(
    val ok: Boolean,
    @SerialName("decision_counts") val decisionCounts: Map<String, Long>
)

@Serializable
internal data class TaskSnapshotJson(
    val name: String,
    val running: Boolean,
    @SerialName("success_count") val successCount: Long,
    @SerialName("error_count") val errorCount: Long,
    @SerialName("last_success_ms") val lastSuccessMs: Long?,
    @SerialName("last_error_ms") val lastErrorMs: Long?,
    @SerialName("last_error") val lastError: String?
)

@Serializable
internal data class TasksResponse(
    val ok: Boolean,
    val tasks: List<TaskSnapshotJson>
)

internal inline fun <reified T> encodeAdminJson(value: T): String =
    adminJson.encodeToString(value)
