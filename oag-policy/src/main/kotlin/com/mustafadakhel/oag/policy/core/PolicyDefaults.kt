package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyDefaults(
    val action: PolicyAction? = null,
    @SerialName("max_body_bytes") val maxBodyBytes: Long? = null,
    @SerialName("enforce_dns_resolution") val enforceDnsResolution: Boolean? = null,
    @SerialName("url_inspection") val urlInspection: PolicyUrlInspection? = null,
    @SerialName("block_dns_exfiltration") val blockDnsExfiltration: Boolean? = null,
    @SerialName("dns_entropy_threshold") val dnsEntropyThreshold: Double? = null,
    @SerialName("dns_min_label_length") val dnsMinLabelLength: Int? = null,
    @SerialName("content_inspection") val contentInspection: PolicyContentInspection? = null,
    @SerialName("max_response_scan_bytes") val maxResponseScanBytes: Long? = null,
    @SerialName("max_bytes_per_host_per_session") val maxBytesPerHostPerSession: Long? = null,
    @SerialName("scan_streaming_responses") val scanStreamingResponses: Boolean? = null,
    @SerialName("injection_scoring") val injectionScoring: PolicyInjectionScoring? = null,
    @SerialName("ml_classifier") val mlClassifier: PolicyMlClassifier? = null,
    @SerialName("outbound_credential_detection") val outboundCredentialDetection: Boolean? = null,
    @SerialName("data_classification") val dataClassification: PolicyDataClassification? = null,
    @SerialName("max_tokens_per_session") val maxTokensPerSession: Long? = null,
    @SerialName("plugin_detection") val pluginDetection: PolicyPluginDetection? = null,
    @SerialName("finding_suppressions") val findingSuppressions: List<PolicyFindingSuppression>? = null
)

@Serializable
data class PolicyUrlInspection(
    @SerialName("max_query_length") val maxQueryLength: Int? = null,
    @SerialName("block_base64_values") val blockBase64Values: Boolean? = null,
    @SerialName("entropy_threshold") val entropyThreshold: Double? = null,
    @SerialName("min_value_length") val minValueLength: Int? = null,
    @SerialName("max_url_length") val maxUrlLength: Int? = null,
    @SerialName("max_path_length") val maxPathLength: Int? = null,
    @SerialName("path_entropy_threshold") val pathEntropyThreshold: Double? = null,
    @SerialName("block_path_traversal") val blockPathTraversal: Boolean? = null,
    @SerialName("block_double_encoding") val blockDoubleEncoding: Boolean? = null,
    @SerialName("block_invalid_percent_encoding") val blockInvalidPercentEncoding: Boolean? = null
)
