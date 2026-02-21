package com.mustafadakhel.oag.audit

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AuditTool(
    val name: String,
    @SerialName("parameter_keys") val parameterKeys: List<String>,
    val parameters: Map<String, String>,
    @SerialName("response_bytes") val responseBytes: Long?,
    @SerialName("duration_ms") val durationMs: Long?,
    @SerialName("error_code") val errorCode: String?
)

@Serializable
data class AuditToolEvent(
    override val timestamp: String? = null,
    @SerialName("schema_version") override val schemaVersion: String = AUDIT_SCHEMA_VERSION,
    @SerialName("event_type") override val eventType: AuditEventType = AuditEventType.TOOL,
    @SerialName("oag_version") override val oagVersion: String,
    @SerialName("policy_hash") val policyHash: String?,
    @SerialName("agent_id") override val agentId: String?,
    @SerialName("session_id") override val sessionId: String?,
    val tool: AuditTool
) : AuditLogEvent {
    override fun withTimestamp(timestamp: String) = copy(timestamp = timestamp)
}

data class ToolCallInput(
    val name: String,
    val parameters: Map<String, Any?>,
    val responseBytes: Long? = null,
    val durationMs: Long? = null,
    val errorCode: String? = null,
    val oagVersion: String,
    val policyHash: String? = null,
    val agentId: String? = null,
    val sessionId: String? = null
)
