package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.ResponseTextBody
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ResponseCredentialDetectorTest {

    private val detector = ResponseCredentialDetector()
    private val ctx = InspectionContext()

    @Test
    fun `detects AWS access key in response`() {
        val input = ResponseTextBody("Your key is AKIAIOSFODNN7EXAMPLE", 200, "application/json")
        val findings = detector.inspect(input, ctx)
        assertTrue(findings.isNotEmpty())
        assertEquals(FindingType.CREDENTIAL, findings.first().type)
        assertTrue(findings.first().recommendedActions.contains(RecommendedAction.REDACT))
    }

    @Test
    fun `returns redaction patterns for detected credentials`() {
        val input = ResponseTextBody("Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 200, "text/plain")
        val patterns = detector.redactionPatterns(input, ctx)
        assertTrue(patterns.isNotEmpty())
        assertTrue(patterns.any { it.name.contains("github") })
    }

    @Test
    fun `returns empty for clean response`() {
        val input = ResponseTextBody("Hello, world!", 200, "text/plain")
        assertTrue(detector.inspect(input, ctx).isEmpty())
        assertTrue(detector.redactionPatterns(input, ctx).isEmpty())
    }
}
