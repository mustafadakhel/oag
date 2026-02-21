package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.WsFrame
import com.mustafadakhel.oag.inspection.spi.DetectorProvider
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class WsFramePluginScannerTest {

    @Test
    fun `returns empty when no WsFrame detectors registered`() {
        val registry = DetectorRegistry.empty()
        val result = scanWsFrame("hello", isText = true, registry, InspectionContext())
        assertTrue(result.findings.isEmpty())
        assertTrue(result.detectorIds.isEmpty())
    }

    @Test
    fun `runs WsFrame detectors and returns findings`() {
        val finding = Finding(
            type = FindingType.CUSTOM,
            severity = FindingSeverity.HIGH,
            confidence = 0.9,
            location = FindingLocation.WebSocket,
            evidence = mapOf("source" to "test-ws-detector"),
            recommendedActions = listOf(RecommendedAction.LOG)
        )
        val detector = Detector<WsFrame> { _, _ -> listOf(finding) }
        val provider = object : DetectorProvider {
            override val id = "ws-test"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(WsFrame::class.java, detector, setOf(FindingType.CUSTOM), "ws-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        val result = scanWsFrame("frame text", isText = true, registry, InspectionContext())

        assertEquals(1, result.findings.size)
        assertEquals("ws-det", result.detectorIds[0])
    }

    @Test
    fun `handles detector exception gracefully`() {
        val detector = Detector<WsFrame> { _, _ -> throw RuntimeException("boom") }
        val provider = object : DetectorProvider {
            override val id = "failing"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(WsFrame::class.java, detector, setOf(FindingType.CUSTOM), "fail-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val errors = mutableListOf<String>()

        val result = scanWsFrame("frame", isText = true, registry, InspectionContext()) { errors.add(it) }

        assertTrue(result.findings.isEmpty())
        assertTrue(errors.isNotEmpty())
    }

    @Test
    fun `does not run ResponseTextBody detectors`() {
        val provider = object : DetectorProvider {
            override val id = "response-only"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(
                    com.mustafadakhel.oag.inspection.ResponseTextBody::class.java,
                    Detector { _, _ -> listOf(Finding(FindingType.CUSTOM, FindingSeverity.HIGH, 1.0, FindingLocation.Body, emptyMap(), listOf(RecommendedAction.DENY))) },
                    setOf(FindingType.CUSTOM),
                    "response-det"
                )
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        val result = scanWsFrame("frame", isText = true, registry, InspectionContext())

        assertTrue(result.findings.isEmpty(), "ResponseTextBody detectors should not run on WsFrame scanning")
    }
}
