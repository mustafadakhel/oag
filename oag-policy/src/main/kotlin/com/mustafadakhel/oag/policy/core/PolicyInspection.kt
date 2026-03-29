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
    @SerialName("max_length") val maxLength: Int? = null,
    @SerialName("trigger_mode") val triggerMode: String? = null,
    @SerialName("uncertain_low") val uncertainLow: Double? = null,
    @SerialName("uncertain_high") val uncertainHigh: Double? = null
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

enum class HallucinationMode {
    OBSERVE,
    ENFORCE
}

enum class TimeoutAction {
    ALLOW,
    DENY
}

@Serializable
data class PolicyHallucinationWeights(
    @SerialName("impossible_claims") val impossibleClaims: Double? = null,
    @SerialName("url_verification") val urlVerification: Double? = null,
    @SerialName("package_verification") val packageVerification: Double? = null,
    @SerialName("logprob_analysis") val logprobAnalysis: Double? = null,
    @SerialName("claim_contradiction") val claimContradiction: Double? = null,
    @SerialName("tool_receipt_verification") val toolReceiptVerification: Double? = null,
    @SerialName("external_nli") val externalNli: Double? = null
)

@Serializable
data class PolicyHallucinationCheck(
    val enabled: Boolean? = null,
    val mode: HallucinationMode? = null,
    @SerialName("deny_threshold") val denyThreshold: Double? = null,
    @SerialName("log_threshold") val logThreshold: Double? = null,
    @SerialName("impossible_claims") val impossibleClaims: Boolean? = null,
    @SerialName("impossible_claims_path") val impossibleClaimsPath: String? = null,
    @SerialName("url_verification") val urlVerification: Boolean? = null,
    @SerialName("url_verification_allowlist") val urlVerificationAllowlist: List<String>? = null,
    @SerialName("package_verification") val packageVerification: Boolean? = null,
    @SerialName("package_registry_mirror") val packageRegistryMirror: String? = null,
    @SerialName("logprob_analysis") val logprobAnalysis: Boolean? = null,
    @SerialName("claim_contradiction") val claimContradiction: Boolean? = null,
    @SerialName("tool_receipt_verification") val toolReceiptVerification: Boolean? = null,
    @SerialName("signal_weights") val signalWeights: PolicyHallucinationWeights? = null,
    @SerialName("external_endpoint_url") val externalEndpointUrl: String? = null,
    @SerialName("external_endpoint_timeout_ms") val externalEndpointTimeoutMs: Int? = null,
    @SerialName("external_endpoint_signing_secret") val externalEndpointSigningSecret: String? = null,
    @SerialName("on_timeout") val onTimeout: TimeoutAction? = null
)
