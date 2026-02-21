package com.mustafadakhel.oag.audit

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.io.Closeable

const val AUDIT_SCHEMA_VERSION = "3"

@Serializable
enum class AuditEventType {
    @SerialName("startup") STARTUP,
    @SerialName("policy_reload") POLICY_RELOAD,
    @SerialName("circuit_breaker") CIRCUIT_BREAKER,
    @SerialName("policy_fetch") POLICY_FETCH,
    @SerialName("admin_access") ADMIN_ACCESS,
    @SerialName("integrity_check") INTEGRITY_CHECK,
    @SerialName("request") REQUEST,
    @SerialName("tool") TOOL
}

sealed interface AuditLogEvent {
    val timestamp: String?
    val schemaVersion: String
    val eventType: AuditEventType
    val oagVersion: String
    val agentId: String?
    val sessionId: String?
    fun withTimestamp(timestamp: String): AuditLogEvent
}

interface AuditExternalSink : Closeable {
    fun log(event: AuditLogEvent)
}

@Serializable
data class AuditTrace(
    @SerialName("trace_id") val traceId: String,
    @SerialName("span_id") val spanId: String,
    @SerialName("trace_flags") val traceFlags: String? = null
)

@Serializable
data class AuditDecision(
    val action: String,
    @SerialName("rule_id") val ruleId: String?,
    @SerialName("reason_code") val reasonCode: String
)

@Serializable
data class AuditRequest(
    val host: String,
    val port: Int,
    val scheme: String,
    val method: String,
    val path: String,
    @SerialName("bytes_out") val bytesOut: Long,
    @SerialName("resolved_ips") val resolvedIps: List<String> = emptyList()
)

@Serializable
data class AuditResponse(
    @SerialName("bytes_in") val bytesIn: Long,
    val status: Int? = null
)

@Serializable
data class AuditRedirectHop(
    val status: Int,
    val location: String,
    @SerialName("target_host") val targetHost: String?,
    @SerialName("target_port") val targetPort: Int?,
    @SerialName("target_scheme") val targetScheme: String?,
    @SerialName("target_path") val targetPath: String?
)

@Serializable
data class AuditSecrets(
    @SerialName("injection_attempted") val injectionAttempted: Boolean,
    val injected: Boolean,
    @SerialName("secret_ids") val secretIds: List<String>,
    @SerialName("secret_versions") val secretVersions: Map<String, String> = emptyMap()
)

@Serializable
data class AuditError(
    val code: String,
    val message: String
)

@Serializable
data class AuditContentInspection(
    @SerialName("body_inspected") val bodyInspected: Boolean = false,
    @SerialName("injection_patterns_matched") val injectionPatternsMatched: List<String>? = null,
    @SerialName("url_entropy_score") val urlEntropyScore: Double? = null,
    @SerialName("dns_entropy_score") val dnsEntropyScore: Double? = null,
    @SerialName("data_budget_used_bytes") val dataBudgetUsedBytes: Long? = null,
    @SerialName("response_truncated") val responseTruncated: Boolean = false,
    @SerialName("streaming_patterns_matched") val streamingPatternsMatched: List<String>? = null,
    @SerialName("injection_score") val injectionScore: Double? = null,
    @SerialName("injection_signals") val injectionSignals: List<String>? = null,
    @SerialName("credentials_detected") val credentialsDetected: List<String>? = null,
    @SerialName("data_classification_matches") val dataClassificationMatches: List<String>? = null,
    @SerialName("data_classification_categories") val dataClassificationCategories: List<String>? = null,
    @SerialName("path_entropy_score") val pathEntropyScore: Double? = null,
    @SerialName("path_traversal_detected") val pathTraversalDetected: Boolean? = null,
    @SerialName("plugin_detector_ids") val pluginDetectorIds: List<String>? = null,
    @SerialName("plugin_finding_count") val pluginFindingCount: Int? = null,
    @SerialName("suppressed_finding_count") val suppressedFindingCount: Int? = null,
    @SerialName("response_plugin_detector_ids") val responsePluginDetectorIds: List<String>? = null,
    @SerialName("response_plugin_finding_count") val responsePluginFindingCount: Int? = null,
    @SerialName("response_data_classification_matches") val responseDataClassificationMatches: List<String>? = null,
    @SerialName("response_data_classification_categories") val responseDataClassificationCategories: List<String>? = null,
    @SerialName("redact_finding_count") val redactFindingCount: Int? = null,
    @SerialName("log_finding_count") val logFindingCount: Int? = null,
    @SerialName("injection_escalating") val injectionEscalating: Boolean? = null,
    @SerialName("streaming_plugin_detector_ids") val streamingPluginDetectorIds: List<String>? = null,
    @SerialName("streaming_plugin_finding_count") val streamingPluginFindingCount: Int? = null
)

@Serializable
data class AuditHeaderRewrite(
    val action: String,
    val header: String
)

@Serializable
data class AuditResponseRewrite(
    val action: String,
    val pattern: String? = null,
    val header: String? = null,
    @SerialName("redaction_count") val redactionCount: Int? = null
)

@Serializable
data class AuditStructuredPayload(
    val protocol: String,
    val method: String? = null,
    @SerialName("operation_name") val operationName: String? = null,
    @SerialName("operation_type") val operationType: String? = null
)

@Serializable
data class AuditTokenUsage(
    @SerialName("prompt_tokens") val promptTokens: Long?,
    @SerialName("completion_tokens") val completionTokens: Long?,
    @SerialName("total_tokens") val totalTokens: Long
)

@Serializable
data class AuditWebSocketSession(
    @SerialName("frame_count") val frameCount: Long,
    @SerialName("client_frames") val clientFrames: Long,
    @SerialName("server_frames") val serverFrames: Long,
    @SerialName("detected_patterns") val detectedPatterns: List<String>? = null,
    @SerialName("data_classification_matches") val dataClassificationMatches: List<String>? = null
)

@Serializable
data class AuditEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.REQUEST,
    @SerialName("oag_version") override val oagVersion: String,
    @SerialName("policy_hash") val policyHash: String,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?,
    @SerialName("request_id") val requestId: String? = null,
    val trace: AuditTrace? = null,
    val request: AuditRequest,
    val response: AuditResponse?,
    val decision: AuditDecision,
    val secrets: AuditSecrets,
    @SerialName("content_inspection") val contentInspection: AuditContentInspection? = null,
    @SerialName("header_rewrites") val headerRewrites: List<AuditHeaderRewrite>? = null,
    @SerialName("retry_count") val retryCount: Int? = null,
    val tags: List<String>? = null,
    @SerialName("redirect_chain") val redirectChain: List<AuditRedirectHop> = emptyList(),
    val errors: List<AuditError> = emptyList(),
    @SerialName("response_rewrites") val responseRewrites: List<AuditResponseRewrite>? = null,
    @SerialName("structured_payload") val structuredPayload: AuditStructuredPayload? = null,
    @SerialName("web_socket_session") val webSocketSession: AuditWebSocketSession? = null,
    @SerialName("agent_profile") val agentProfile: String? = null,
    @SerialName("phase_timings") val phaseTimings: Map<String, Double>? = null,
    @SerialName("dry_run_override") val dryRunOverride: Boolean? = null,
    @SerialName("token_usage") val tokenUsage: AuditTokenUsage? = null
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}
