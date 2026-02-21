package com.mustafadakhel.oag.inspection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DetectorTest {

    @Test
    fun `detector can be implemented as lambda`() {
        val detector = Detector<TextBody> { input, _ ->
            if ("secret" in input.text) {
                listOf(
                    Finding(
                        type = FindingType.CREDENTIAL,
                        severity = FindingSeverity.HIGH,
                        confidence = 0.9,
                        location = FindingLocation.Body,
                        evidence = mapOf("matched" to "secret"),
                        recommendedActions = listOf(RecommendedAction.DENY)
                    )
                )
            } else {
                emptyList()
            }
        }

        val ctx = InspectionContext(host = "api.example.com")
        assertTrue(detector.inspect(TextBody("hello"), ctx).isEmpty())
        assertEquals(1, detector.inspect(TextBody("my secret key"), ctx).size)
    }

    @Test
    fun `inspection context defaults are null`() {
        val ctx = InspectionContext()
        assertEquals(null, ctx.host)
        assertEquals(null, ctx.method)
        assertEquals(null, ctx.path)
        assertEquals(null, ctx.ruleId)
        assertEquals(null, ctx.agentId)
    }

    @Test
    fun `detector returns empty list for clean input`() {
        val noopDetector = Detector<Headers> { _, _ -> emptyList() }
        val findings = noopDetector.inspect(Headers(listOf(HeaderEntry("Host", "example.com"))), InspectionContext())
        assertTrue(findings.isEmpty())
    }
}
