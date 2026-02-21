package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.audit.AuditHeaderRewrite
import com.mustafadakhel.oag.audit.AuditRedirectHop
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.inspection.content.AhoCorasickAutomaton
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.enforcement.TokenUsage

import java.io.IOException

data class ContentInspectionResult(
    val decision: PolicyDecision?,
    val matchedPatterns: List<String> = emptyList(),
    val injectionScore: Double? = null,
    val injectionSignals: List<String> = emptyList()
)

data class ExfiltrationCheckResult(
    val decision: PolicyDecision?,
    val maxEntropy: Double? = null
)

data class ResponseRelayResult(
    val bytesIn: Long,
    val statusCode: Int? = null,
    val decisionOverride: PolicyDecision? = null,
    val redirectChain: List<AuditRedirectHop> = emptyList(),
    val streamingMatchedPatterns: List<String> = emptyList(),
    val truncationAction: EnforcementAction.Truncate? = null,
    val redactionActions: List<EnforcementAction.Redact> = emptyList(),
    val connectionReusable: Boolean = false,
    val tokenUsage: TokenUsage? = null,
    val responsePluginFindings: ResponseScanResult? = null,
    val responseDataClassification: DataClassificationResult? = null,
    val streamingPluginFindings: StreamingResponseScanResult? = null
)

data class StreamingScanResult(
    val bytesRelayed: Long,
    val matchedPatterns: List<String>,
    val truncated: Boolean,
    val accumulatedBody: String? = null
)

data class RegexPatternEntry(val source: String, val regex: Regex)

data class StreamingScanner(
    val automaton: AhoCorasickAutomaton?,
    val regexPatterns: List<RegexPatternEntry>,
    val accumulateForPlugins: Boolean = false
)

data class DataClassificationResult(
    val decision: PolicyDecision?,
    val matches: List<String> = emptyList(),
    val categories: List<String> = emptyList()
)

data class PathAnalysisResult(
    val decision: PolicyDecision?,
    val pathEntropyScore: Double? = null,
    val pathTraversalDetected: Boolean = false
)

data class HeaderRewriteResult(
    val headers: Map<String, String>,
    val auditEntries: List<AuditHeaderRewrite>
)

sealed class RequestBodyException(message: String) : IOException(message) {
    class Truncated : RequestBodyException("Truncated request body")
    class Timeout : RequestBodyException("Client request body timeout")
    class ReadFailure : RequestBodyException("Client request body read failure")
}
