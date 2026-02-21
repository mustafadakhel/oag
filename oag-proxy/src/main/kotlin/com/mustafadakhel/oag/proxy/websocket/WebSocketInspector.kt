package com.mustafadakhel.oag.proxy.websocket

import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.content.CredentialPatterns
import com.mustafadakhel.oag.inspection.content.SensitiveDataPatterns
import com.mustafadakhel.oag.inspection.injection.InjectionPatterns
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.normalizeContent
import com.mustafadakhel.oag.pipeline.inspection.matchCustomAndAnchoredPatterns
import com.mustafadakhel.oag.pipeline.inspection.scanWsFrame
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification

import java.util.concurrent.ConcurrentHashMap

internal class WebSocketInspector(
    private val contentInspection: PolicyContentInspection?,
    private val dataClassification: PolicyDataClassification?,
    private val detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    private val inspectionContext: InspectionContext? = null
) {
    private val _detectedPatterns: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val detectedPatterns: Set<String> get() = _detectedPatterns

    private val _dataClassificationMatches: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val dataClassificationMatches: Set<String> get() = _dataClassificationMatches

    private val _pluginDetectorIds: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val pluginDetectorIds: Set<String> get() = _pluginDetectorIds

    fun inspectFrame(frame: WebSocketFrame, direction: WsDirection): FrameInspectionResult {
        if (!frame.isText) return FrameInspectionResult.ALLOW
        val text = frame.textPayload
        val normalized = text.normalizeContent()
        var deny = false
        val isClientFrame = direction == WsDirection.CLIENT_TO_SERVER
        val builtinEnabled = contentInspection?.enableBuiltinPatterns == true
        if (builtinEnabled) {
            if (isClientFrame) {
                val injectionMatches = InjectionPatterns.matches(normalized)
                _detectedPatterns.addAll(injectionMatches)
                if (injectionMatches.isNotEmpty()) deny = true
            }
            _detectedPatterns.addAll(CredentialPatterns.matches(normalized))
        }
        if (isClientFrame && contentInspection != null) {
            val customMatches = matchCustomAndAnchoredPatterns(contentInspection, normalized)
            if (customMatches.isNotEmpty()) {
                _detectedPatterns.addAll(customMatches)
                deny = true
            }
        }
        if (dataClassification?.enableBuiltinPatterns == true) {
            val classMatches = SensitiveDataPatterns.matchesByCategory(normalized, dataClassification.categories).values.flatten()
            _dataClassificationMatches.addAll(classMatches)
            if (classMatches.isNotEmpty()) deny = true
        }
        if (inspectionContext != null) {
            val scanResult = scanWsFrame(
                text = normalized,
                isText = true,
                registry = detectorRegistry,
                inspectionContext = inspectionContext
            )
            if (scanResult.findings.isNotEmpty()) {
                _pluginDetectorIds.addAll(scanResult.detectorIds)
                if (scanResult.findings.any { f -> f.recommendedActions.any { it == RecommendedAction.DENY } }) {
                    deny = true
                }
            }
        }
        return if (deny) FrameInspectionResult.DENY else FrameInspectionResult.ALLOW
    }

    enum class FrameInspectionResult { ALLOW, DENY }
}
