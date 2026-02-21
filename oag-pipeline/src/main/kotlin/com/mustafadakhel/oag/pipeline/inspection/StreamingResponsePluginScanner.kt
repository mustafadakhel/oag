package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.StreamingResponseBody
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

data class StreamingResponseScanResult(
    val findings: List<Finding>,
    val detectorIds: List<String>,
    val truncated: Boolean
)

fun scanStreamingResponseBody(
    accumulatedText: String,
    statusCode: Int,
    contentType: String?,
    truncated: Boolean,
    registry: DetectorRegistry,
    inspectionContext: InspectionContext,
    onError: (String) -> Unit = {}
): StreamingResponseScanResult {
    val regs = registry.registrationsFor(StreamingResponseBody::class.java)
    if (regs.isEmpty()) return StreamingResponseScanResult(emptyList(), emptyList(), truncated)

    val artifact = StreamingResponseBody(
        accumulatedText = accumulatedText,
        statusCode = statusCode,
        contentType = contentType,
        truncated = truncated
    )
    val matchedIds = mutableListOf<String>()
    val findings = regs.flatMap { reg ->
        val results = runCatching { reg.detector.inspect(artifact, inspectionContext) }
            .onFailure { e -> onError("streaming response detector '${reg.id}' failed: ${e.message}") }
            .getOrDefault(emptyList())
        if (results.isNotEmpty()) matchedIds.add(reg.id)
        results
    }

    return StreamingResponseScanResult(
        findings = findings,
        detectorIds = matchedIds.distinct(),
        truncated = truncated
    )
}
