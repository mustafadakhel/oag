package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyRule(
    val id: String? = null,
    val host: String? = null,
    val methods: List<String>? = null,
    val paths: List<String>? = null,
    val secrets: List<String>? = null,
    @SerialName("ip_ranges") val ipRanges: List<String>? = null,
    @SerialName("max_body_bytes") val maxBodyBytes: Long? = null,
    val conditions: PolicyCondition? = null,
    @SerialName("reason_code") val reasonCode: String? = null,
    @SerialName("rate_limit") val rateLimit: PolicyRateLimit? = null,
    @SerialName("body_match") val bodyMatch: PolicyBodyMatch? = null,
    @SerialName("response_body_match") val responseBodyMatch: PolicyBodyMatch? = null,
    @SerialName("content_inspection") val contentInspection: PolicyContentInspection? = null,
    @SerialName("skip_content_inspection") val skipContentInspection: Boolean? = null,
    @SerialName("skip_response_scanning") val skipResponseScanning: Boolean? = null,
    @SerialName("tls_inspect") val tlsInspect: Boolean? = null,
    @SerialName("header_rewrites") val headerRewrites: List<PolicyHeaderRewrite>? = null,
    @SerialName("connect_timeout_ms") val connectTimeoutMs: Int? = null,
    @SerialName("read_timeout_ms") val readTimeoutMs: Int? = null,
    val retry: PolicyRetry? = null,
    @SerialName("header_match") val headerMatch: List<PolicyHeaderMatch>? = null,
    @SerialName("query_match") val queryMatch: List<PolicyQueryMatch>? = null,
    val tags: List<String>? = null,
    @SerialName("error_response") val errorResponse: PolicyErrorResponse? = null,
    @SerialName("skip_outbound_credential_detection") val skipOutboundCredentialDetection: Boolean? = null,
    @SerialName("data_classification") val dataClassification: PolicyDataClassification? = null,
    @SerialName("skip_data_classification") val skipDataClassification: Boolean? = null,
    @SerialName("response_rewrites") val responseRewrites: List<PolicyResponseRewrite>? = null,
    @SerialName("payload_match") val payloadMatch: List<PolicyPayloadMatch>? = null,
    @SerialName("plugin_detection") val pluginDetection: PolicyPluginDetection? = null,
    @SerialName("skip_plugin_detection") val skipPluginDetection: Boolean? = null,
    @SerialName("finding_suppressions") val findingSuppressions: List<PolicyFindingSuppression>? = null,
    @SerialName("webhook_events") val webhookEvents: List<String>? = null
)

@Serializable
data class PolicyCondition(
    val scheme: String? = null,
    val ports: List<Int>? = null
)

@Serializable
data class PolicyRateLimit(
    @SerialName("requests_per_second") val requestsPerSecond: Double? = null,
    val burst: Int? = null
)

@Serializable
data class PolicyRetry(
    @SerialName("max_retries") val maxRetries: Int? = null,
    @SerialName("retry_delay_ms") val retryDelayMs: Long? = null
)

@Serializable
data class SecretScope(
    val id: String? = null,
    val hosts: List<String>? = null,
    val methods: List<String>? = null,
    val paths: List<String>? = null,
    @SerialName("ip_ranges") val ipRanges: List<String>? = null
)

fun PolicyRule.shouldNotifyWebhook(eventType: String): Boolean {
    val events = webhookEvents ?: return true
    return events.isEmpty() || eventType in events
}
