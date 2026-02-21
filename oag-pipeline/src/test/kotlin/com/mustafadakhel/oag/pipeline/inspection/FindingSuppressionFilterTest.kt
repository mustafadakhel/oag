package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.policy.core.PolicyFindingSuppression

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FindingSuppressionFilterTest {

    @Test
    fun `no suppressions returns all findings`() {
        val findings = listOf(testFinding("CREDENTIAL"))
        val result = suppressFindings(findings, null, "api.example.com")
        assertEquals(1, result.kept.size)
        assertTrue(result.suppressed.isEmpty())
    }

    @Test
    fun `empty suppressions returns all findings`() {
        val findings = listOf(testFinding("CREDENTIAL"))
        val result = suppressFindings(findings, emptyList(), "api.example.com")
        assertEquals(1, result.kept.size)
    }

    @Test
    fun `suppresses by finding type`() {
        val suppressions = listOf(PolicyFindingSuppression(findingType = "CREDENTIAL"))
        val findings = listOf(testFinding("CREDENTIAL"), testFinding("PII"))
        val result = suppressFindings(findings, suppressions, "api.example.com")
        assertEquals(1, result.kept.size)
        assertEquals(FindingType.PII, result.kept[0].type)
        assertEquals(1, result.suppressed.size)
    }

    @Test
    fun `suppresses by detector id`() {
        val suppressions = listOf(PolicyFindingSuppression(detectorId = "phone-detector"))
        val findings = listOf(
            testFinding("CUSTOM", source = "phone-detector"),
            testFinding("CUSTOM", source = "email-detector")
        )
        val result = suppressFindings(findings, suppressions, "api.example.com")
        assertEquals(1, result.kept.size)
        assertEquals("email-detector", result.kept[0].evidence["source"])
        assertEquals(1, result.suppressed.size)
    }

    @Test
    fun `suppresses by pattern match in evidence`() {
        val suppressions = listOf(PolicyFindingSuppression(pattern = "AKIAIOSFODNN7EXAMPLE"))
        val findings = listOf(
            testFinding("CREDENTIAL", pattern = "AKIAIOSFODNN7EXAMPLE"),
            testFinding("CREDENTIAL", pattern = "ghp_realtoken")
        )
        val result = suppressFindings(findings, suppressions, "api.example.com")
        assertEquals(1, result.kept.size)
        assertEquals(1, result.suppressed.size)
    }

    @Test
    fun `suppresses by host exact match`() {
        val suppressions = listOf(PolicyFindingSuppression(findingType = "CREDENTIAL", hosts = listOf("dev.example.com")))
        val findings = listOf(testFinding("CREDENTIAL"))

        val devResult = suppressFindings(findings, suppressions, "dev.example.com")
        assertEquals(0, devResult.kept.size)

        val prodResult = suppressFindings(findings, suppressions, "prod.example.com")
        assertEquals(1, prodResult.kept.size)
    }

    @Test
    fun `suppresses by host wildcard`() {
        val suppressions = listOf(PolicyFindingSuppression(findingType = "PII", hosts = listOf("*.dev.corp")))
        val findings = listOf(testFinding("PII"))

        val matchResult = suppressFindings(findings, suppressions, "api.dev.corp")
        assertEquals(0, matchResult.kept.size)

        val noMatchResult = suppressFindings(findings, suppressions, "api.prod.corp")
        assertEquals(1, noMatchResult.kept.size)
    }

    @Test
    fun `multiple suppressions rules are OR-ed`() {
        val suppressions = listOf(
            PolicyFindingSuppression(findingType = "CREDENTIAL"),
            PolicyFindingSuppression(findingType = "PII")
        )
        val findings = listOf(testFinding("CREDENTIAL"), testFinding("PII"), testFinding("CUSTOM"))
        val result = suppressFindings(findings, suppressions, "api.example.com")
        assertEquals(1, result.kept.size)
        assertEquals(FindingType.CUSTOM, result.kept[0].type)
        assertEquals(2, result.suppressed.size)
    }

    @Test
    fun `suppression requires all specified fields to match`() {
        val suppressions = listOf(PolicyFindingSuppression(findingType = "CREDENTIAL", hosts = listOf("dev.example.com")))
        val findings = listOf(testFinding("CREDENTIAL"))

        val matchBoth = suppressFindings(findings, suppressions, "dev.example.com")
        assertEquals(0, matchBoth.kept.size)

        val matchTypeOnly = suppressFindings(findings, suppressions, "prod.example.com")
        assertEquals(1, matchTypeOnly.kept.size)
    }

    private fun testFinding(
        type: String,
        source: String = "test",
        pattern: String = "test-pattern"
    ) = Finding(
        type = FindingType.valueOf(type),
        severity = FindingSeverity.HIGH,
        confidence = 0.9,
        location = FindingLocation.Body,
        evidence = mapOf("source" to source, "pattern" to pattern),
        recommendedActions = listOf(RecommendedAction.DENY)
    )
}
