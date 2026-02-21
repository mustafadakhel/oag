package com.mustafadakhel.oag.inspection

import com.mustafadakhel.oag.FindingSeverityLabels
import com.mustafadakhel.oag.FindingTypeLabels
import com.mustafadakhel.oag.label

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FindingTest {

    @Test
    fun `finding preserves all fields`() {
        val finding = Finding(
            type = FindingType.CREDENTIAL,
            severity = FindingSeverity.HIGH,
            confidence = 0.95,
            location = FindingLocation.Body,
            evidence = mapOf("pattern" to "bearer_token", "matched" to "Bearer sk-***"),
            recommendedActions = listOf(RecommendedAction.DENY, RecommendedAction.LOG)
        )

        assertEquals(FindingType.CREDENTIAL, finding.type)
        assertEquals(FindingSeverity.HIGH, finding.severity)
        assertEquals(0.95, finding.confidence)
        assertEquals(FindingLocation.Body, finding.location)
        assertEquals(2, finding.evidence.size)
        assertEquals(listOf(RecommendedAction.DENY, RecommendedAction.LOG), finding.recommendedActions)
    }

    @Test
    fun `finding allows null location`() {
        val finding = Finding(
            type = FindingType.PROMPT_INJECTION,
            severity = FindingSeverity.CRITICAL,
            confidence = 0.88,
            location = null,
            evidence = mapOf("classifier" to "heuristic"),
            recommendedActions = emptyList()
        )

        assertNull(finding.location)
    }

    @Test
    fun `finding severity labels match lowercase names`() {
        assertEquals("low", FindingSeverity.LOW.label())
        assertEquals("medium", FindingSeverity.MEDIUM.label())
        assertEquals("high", FindingSeverity.HIGH.label())
        assertEquals("critical", FindingSeverity.CRITICAL.label())
    }

    @Test
    fun `FindingSeverity entries match FindingSeverityLabels valid set`() {
        assertEquals(
            FindingSeverity.entries.map { it.label() }.toSet(),
            FindingSeverityLabels.valid
        )
    }

    @Test
    fun `FindingType entries match FindingTypeLabels valid set`() {
        assertEquals(
            FindingType.entries.map { it.label() }.toSet(),
            FindingTypeLabels.valid
        )
    }
}
