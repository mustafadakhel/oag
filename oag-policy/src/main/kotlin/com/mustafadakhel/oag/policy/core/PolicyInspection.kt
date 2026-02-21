package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

enum class PatternAnchor {
    ANY,
    START_OF_MESSAGE,
    STANDALONE
}

@Serializable
data class PolicyAnchoredPattern(
    val pattern: String,
    val anchor: PatternAnchor? = null
)

@Serializable
data class PolicyContentInspection(
    @SerialName("enable_builtin_patterns") val enableBuiltinPatterns: Boolean? = null,
    @SerialName("custom_patterns") val customPatterns: List<String>? = null,
    @SerialName("anchored_patterns") val anchoredPatterns: List<PolicyAnchoredPattern>? = null,
    @SerialName("scan_streaming_responses") val scanStreamingResponses: Boolean? = null,
    @SerialName("scan_websocket_frames") val scanWebSocketFrames: Boolean? = null
)

enum class InjectionScoringMode {
    BINARY,
    SCORE
}

@Serializable
data class PolicyCategoryWeight(
    val category: String,
    val weight: Double
)

@Serializable
data class PolicyInjectionScoring(
    val mode: InjectionScoringMode? = null,
    @SerialName("deny_threshold") val denyThreshold: Double? = null,
    @SerialName("log_threshold") val logThreshold: Double? = null,
    @SerialName("entropy_weight") val entropyWeight: Double? = null,
    @SerialName("entropy_baseline") val entropyBaseline: Double? = null,
    @SerialName("category_weights") val categoryWeights: List<PolicyCategoryWeight>? = null
)

@Serializable
data class PolicyMlClassifier(
    val enabled: Boolean? = null,
    @SerialName("model_path") val modelPath: String? = null,
    @SerialName("tokenizer_path") val tokenizerPath: String? = null,
    @SerialName("confidence_threshold") val confidenceThreshold: Double? = null,
    @SerialName("max_length") val maxLength: Int? = null
)

@Serializable
data class PolicyDataClassification(
    @SerialName("enable_builtin_patterns") val enableBuiltinPatterns: Boolean? = null,
    @SerialName("custom_patterns") val customPatterns: List<String>? = null,
    val categories: List<String>? = null,
    @SerialName("scan_responses") val scanResponses: Boolean? = null
)

@Serializable
data class PolicyFindingSuppression(
    @SerialName("detector_id") val detectorId: String? = null,
    @SerialName("finding_type") val findingType: String? = null,
    val pattern: String? = null,
    val hosts: List<String>? = null
)

@Serializable
data class PolicyPluginDetection(
    val enabled: Boolean? = null,
    @SerialName("detector_ids") val detectorIds: List<String>? = null,
    @SerialName("exclude_detector_ids") val excludeDetectorIds: List<String>? = null,
    @SerialName("scan_responses") val scanResponses: Boolean? = null,
    @SerialName("deny_severity_threshold") val denySeverityThreshold: String? = null
)
