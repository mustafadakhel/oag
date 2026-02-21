package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.ResponseTextBody
import com.mustafadakhel.oag.inspection.spi.DetectorProvider
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResponsePluginScannerTest {

    @Test
    fun `returns empty when no response detectors registered`() {
        val registry = DetectorRegistry.empty()
        val result = scanResponseBody("hello", 200, "text/plain", registry, InspectionContext())
        assertTrue(result.findings.isEmpty())
        assertTrue(result.detectorIds.isEmpty())
    }

    @Test
    fun `runs response detectors and returns findings`() {
        val finding = Finding(
            type = FindingType.CUSTOM,
            severity = FindingSeverity.HIGH,
            confidence = 0.9,
            location = FindingLocation.Body,
            evidence = mapOf("source" to "test-response-detector"),
            recommendedActions = listOf(RecommendedAction.LOG)
        )
        val detector = Detector<ResponseTextBody> { _, _ -> listOf(finding) }
        val provider = object : DetectorProvider {
            override val id = "response-test"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(ResponseTextBody::class.java, detector, setOf(FindingType.CUSTOM), "resp-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        val result = scanResponseBody("response body", 200, "application/json", registry, InspectionContext())

        assertEquals(1, result.findings.size)
        assertEquals("resp-det", result.detectorIds[0])
    }

    @Test
    fun `handles detector exception gracefully`() {
        val detector = Detector<ResponseTextBody> { _, _ -> throw RuntimeException("boom") }
        val provider = object : DetectorProvider {
            override val id = "failing"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(ResponseTextBody::class.java, detector, setOf(FindingType.CUSTOM), "fail-det")
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val errors = mutableListOf<String>()

        val result = scanResponseBody("body", 200, null, registry, InspectionContext()) { errors.add(it) }

        assertTrue(result.findings.isEmpty())
        assertTrue(errors.isNotEmpty())
    }

    @Test
    fun `does not run request TextBody detectors`() {
        val provider = object : DetectorProvider {
            override val id = "request-only"
            override val description = "test"
            override fun detectors() = listOf(
                DetectorRegistration(
                    com.mustafadakhel.oag.inspection.TextBody::class.java,
                    Detector { _, _ -> listOf(Finding(FindingType.CUSTOM, FindingSeverity.HIGH, 1.0, FindingLocation.Body, emptyMap(), listOf(RecommendedAction.DENY))) },
                    setOf(FindingType.CUSTOM),
                    "request-det"
                )
            )
        }
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        val result = scanResponseBody("body", 200, null, registry, InspectionContext())

        assertTrue(result.findings.isEmpty(), "Request TextBody detectors should not run on response scanning")
    }
}
