package com.mustafadakhel.oag.audit

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AuditStartupConfig(
    @SerialName("policy_path") val policyPath: String,
    @SerialName("policy_public_key_path") val policyPublicKeyPath: String?,
    @SerialName("policy_require_signature") val policyRequireSignature: Boolean,
    @SerialName("log_path") val logPath: String?,
    @SerialName("listen_host") val listenHost: String,
    @SerialName("listen_port") val listenPort: Int,
    @SerialName("max_threads") val maxThreads: Int,
    @SerialName("secret_env_prefix") val secretEnvPrefix: String,
    @SerialName("secret_provider") val secretProvider: String,
    @SerialName("secret_file_dir") val secretFileDir: String?,
    @SerialName("dry_run") val dryRun: Boolean,
    @SerialName("block_ip_literals") val blockIpLiterals: Boolean,
    @SerialName("enforce_redirect_policy") val enforceRedirectPolicy: Boolean,
    @SerialName("block_private_resolved_ips") val blockPrivateResolvedIps: Boolean,
    @SerialName("connect_timeout_ms") val connectTimeoutMs: Int,
    @SerialName("read_timeout_ms") val readTimeoutMs: Int,
    @SerialName("otel_exporter") val otelExporter: String,
    @SerialName("otel_endpoint") val otelEndpoint: String?,
    @SerialName("otel_headers_keys") val otelHeadersKeys: List<String>,
    @SerialName("otel_timeout_ms") val otelTimeoutMs: Int?,
    @SerialName("otel_service_name") val otelServiceName: String?
)

@Serializable
data class AuditStartupEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.STARTUP,
    @SerialName("oag_version") override val oagVersion: String,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?,
    val config: AuditStartupConfig,
    @SerialName("config_fingerprint") val configFingerprint: String? = null
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

@Serializable
data class AuditPolicyReloadEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.POLICY_RELOAD,
    @SerialName("oag_version") override val oagVersion: String,
    @SerialName("previous_policy_hash") val previousPolicyHash: String,
    @SerialName("new_policy_hash") val newPolicyHash: String?,
    val changed: Boolean,
    val success: Boolean,
    @SerialName("error_message") val errorMessage: String? = null,
    val trigger: String? = null,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

@Serializable
data class AuditCircuitBreakerEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.CIRCUIT_BREAKER,
    @SerialName("oag_version") override val oagVersion: String,
    val host: String,
    @SerialName("previous_state") val previousState: String,
    @SerialName("new_state") val newState: String,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

@Serializable
data class AuditPolicyFetchEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.POLICY_FETCH,
    @SerialName("oag_version") override val oagVersion: String,
    @SerialName("source_url") val sourceUrl: String,
    val success: Boolean,
    val changed: Boolean = false,
    @SerialName("content_hash") val contentHash: String? = null,
    @SerialName("error_message") val errorMessage: String? = null,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

@Serializable
data class AuditAdminAccessEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.ADMIN_ACCESS,
    @SerialName("oag_version") override val oagVersion: String,
    val endpoint: String,
    @SerialName("source_ip") val sourceIp: String,
    val allowed: Boolean,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

@Serializable
data class AuditIntegrityCheckEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.INTEGRITY_CHECK,
    @SerialName("oag_version") override val oagVersion: String,
    val status: String,
    @SerialName("policy_hash_match") val policyHashMatch: Boolean,
    @SerialName("config_fingerprint_match") val configFingerprintMatch: Boolean,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}
