package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.WsFrame
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

data class WsFrameScanResult(
    val findings: List<Finding>,
    val detectorIds: List<String>
)

fun scanWsFrame(
    text: String,
    isText: Boolean,
    registry: DetectorRegistry,
    inspectionContext: InspectionContext,
    onError: (String) -> Unit = {}
): WsFrameScanResult {
    val regs = registry.registrationsFor(WsFrame::class.java)
    if (regs.isEmpty()) return WsFrameScanResult(emptyList(), emptyList())

    val artifact = WsFrame(text = text, isText = isText)
    val matchedIds = mutableListOf<String>()
    val findings = regs.flatMap { reg ->
        val results = runCatching { reg.detector.inspect(artifact, inspectionContext) }
            .onFailure { e -> onError("ws frame detector '${reg.id}' failed: ${e.message}") }
            .getOrDefault(emptyList())
        if (results.isNotEmpty()) matchedIds.add(reg.id)
        results
    }

    return WsFrameScanResult(
        findings = findings,
        detectorIds = matchedIds.distinct()
    )
}
