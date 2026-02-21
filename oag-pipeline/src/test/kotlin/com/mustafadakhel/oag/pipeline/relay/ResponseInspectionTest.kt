package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.REDACTED_SENTINEL
import com.mustafadakhel.oag.inspection.RedactionPattern
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResponseInspectionTest {

    @Test
    fun `applyPolicyRedactions replaces matching patterns`() {
        val rewrites = listOf<PolicyResponseRewrite>(
            PolicyResponseRewrite.Redact(pattern = "\\d{3}-\\d{2}-\\d{4}")
        )
        val result = applyPolicyRedactions("SSN: 123-45-6789", rewrites) {}
        assertTrue(result.transformedText.contains(REDACTED_SENTINEL))
        assertEquals(1, result.actions.size)
    }

    @Test
    fun `applyPolicyRedactions with no matches returns original`() {
        val rewrites = listOf<PolicyResponseRewrite>(
            PolicyResponseRewrite.Redact(pattern = "NOMATCH")
        )
        val result = applyPolicyRedactions("hello world", rewrites) {}
        assertEquals("hello world", result.transformedText)
        assertTrue(result.actions.isEmpty())
    }

    @Test
    fun `evaluateBodyMatch returns true when bodyMatch is null`() {
        assertTrue(evaluateBodyMatch("any text", null) {})
    }

    @Test
    fun `evaluateBodyMatch returns true when body matches`() {
        val match = PolicyBodyMatch(contains = listOf("ok"))
        assertTrue(evaluateBodyMatch("response ok", match) {})
    }

    @Test
    fun `evaluateBodyMatch returns false when body does not match`() {
        val match = PolicyBodyMatch(contains = listOf("ok"))
        assertFalse(evaluateBodyMatch("response fail", match) {})
    }

    @Test
    fun `applyFindingRedactions replaces patterns`() {
        val patterns = listOf(
            RedactionPattern("ssn", Regex("\\d{3}-\\d{2}-\\d{4}"))
        )
        val result = applyFindingRedactions("SSN: 123-45-6789", patterns)
        assertTrue(result.transformedText.contains(REDACTED_SENTINEL))
        assertEquals(1, result.actions.size)
        assertEquals("ssn", result.actions[0].target)
    }

    @Test
    fun `applyFindingRedactions with no matches returns original`() {
        val patterns = listOf(
            RedactionPattern("ssn", Regex("NOMATCH"))
        )
        val result = applyFindingRedactions("hello", patterns)
        assertEquals("hello", result.transformedText)
        assertTrue(result.actions.isEmpty())
    }
}
