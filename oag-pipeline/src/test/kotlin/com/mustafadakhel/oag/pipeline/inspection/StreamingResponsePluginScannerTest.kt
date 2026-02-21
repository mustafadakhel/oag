package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.StreamingResponseBody
import com.mustafadakhel.oag.inspection.spi.DetectorProvider
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class StreamingResponsePluginScannerTest {

    @Test
    fun `returns empty when no streaming detectors registered`() {
        val registry = DetectorRegistry.empty()
        val result = scanStreamingResponseBody("text", 200, "text/event-stream", false, registry, InspectionContext())
        assertTrue(result.findings.isEmpty())
        assertTrue(result.detectorIds.isEmpty())
    }

    @Test
    fun `runs streaming detectors and returns findings`() {
        val finding = Finding(
            type = FindingType.PII,
            severity = FindingSeverity.HIGH,
            confidence = 0.9,
            location = FindingLocation.StreamingResponse,
            evidence = mapOf("source" to "test-streaming-detector"),
            recommendedActions = listOf(RecommendedAction.LOG)
        )
        val detector = Detector<StreamingResponseBody> { _, _ -> listOf(finding) }
        val provider = object : DetectorProvider {
            override val id = "streaming-test"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(StreamingResponseBody::class.java, detector, setOf(FindingType.PII), "stream-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        val result = scanStreamingResponseBody("accumulated text", 200, "text/event-stream", false, registry, InspectionContext())

        assertEquals(1, result.findings.size)
        assertEquals("stream-det", result.detectorIds[0])
        assertEquals(false, result.truncated)
    }

    @Test
    fun `handles detector exception gracefully`() {
        val detector = Detector<StreamingResponseBody> { _, _ -> throw RuntimeException("boom") }
        val provider = object : DetectorProvider {
            override val id = "failing"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(StreamingResponseBody::class.java, detector, setOf(FindingType.CUSTOM), "fail-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val errors = mutableListOf<String>()

        val result = scanStreamingResponseBody("text", 200, null, false, registry, InspectionContext()) { errors.add(it) }

        assertTrue(result.findings.isEmpty())
        assertTrue(errors.isNotEmpty())
    }

    @Test
    fun `passes truncated flag through`() {
        val registry = DetectorRegistry.empty()
        val result = scanStreamingResponseBody("partial...", 200, null, true, registry, InspectionContext())
        assertTrue(result.truncated)
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

        val result = scanStreamingResponseBody("text", 200, null, false, registry, InspectionContext())

        assertTrue(result.findings.isEmpty(), "ResponseTextBody detectors should not run on streaming scanning")
    }
}
