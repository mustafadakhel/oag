package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.RedactingDetector
import com.mustafadakhel.oag.inspection.RedactionPattern
import com.mustafadakhel.oag.inspection.ResponseTextBody
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

data class ResponseScanResult(
    val findings: List<Finding>,
    val detectorIds: List<String>,
    val redactionPatterns: List<RedactionPattern> = emptyList()
)

fun scanResponseBody(
    responseBody: String,
    statusCode: Int,
    contentType: String?,
    registry: DetectorRegistry,
    inspectionContext: InspectionContext,
    onError: (String) -> Unit = {}
): ResponseScanResult {
    val regs = registry.registrationsFor(ResponseTextBody::class.java)
    if (regs.isEmpty()) return ResponseScanResult(emptyList(), emptyList())

    val artifact = ResponseTextBody(text = responseBody, statusCode = statusCode, contentType = contentType)
    val matchedIds = mutableListOf<String>()
    val allRedactionPatterns = mutableListOf<RedactionPattern>()
    val findings = regs.flatMap { reg ->
        val results = runCatching { reg.detector.inspect(artifact, inspectionContext) }
            .onFailure { e -> onError("response plugin detector '${reg.id}' failed: ${e.message}") }
            .getOrDefault(emptyList())
        if (results.isNotEmpty()) matchedIds.add(reg.id)
        if (results.any { it.recommendedActions.any { a -> a == RecommendedAction.REDACT } }) {
            val detector = reg.detector
            if (detector is RedactingDetector<*>) {
                @Suppress("UNCHECKED_CAST")
                val redacting = detector as RedactingDetector<ResponseTextBody>
                val patterns = runCatching { redacting.redactionPatterns(artifact, inspectionContext) }
                    .onFailure { e -> onError("response plugin detector '${reg.id}' redactionPatterns failed: ${e.message}") }
                    .getOrDefault(emptyList())
                allRedactionPatterns.addAll(patterns)
            }
        }
        results
    }

    return ResponseScanResult(
        findings = findings,
        detectorIds = matchedIds.distinct(),
        redactionPatterns = allRedactionPatterns
    )
}
