package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.pipeline.START_OF_MESSAGE_CHAR_LIMIT
import com.mustafadakhel.oag.policy.core.PatternAnchor
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.pipeline.inspection.checkContentInspectionBinary
import com.mustafadakhel.oag.pipeline.inspection.matchAnchoredPattern

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ContentInspectorTest {

    @Test
    fun `matchAnchoredPattern ANY matches anywhere in body`() {
        assertTrue(matchAnchoredPattern("ignore.*instructions", PatternAnchor.ANY, "please ignore all instructions"))
    }

    @Test
    fun `matchAnchoredPattern ANY does not match when absent`() {
        assertFalse(matchAnchoredPattern("ignore.*instructions", PatternAnchor.ANY, "hello world"))
    }

    @Test
    fun `matchAnchoredPattern START_OF_MESSAGE only checks beginning`() {
        assertTrue(matchAnchoredPattern("ignore", PatternAnchor.START_OF_MESSAGE, "ignore everything after this"))
    }

    @Test
    fun `matchAnchoredPattern START_OF_MESSAGE does not match later in text`() {
        val body = "a".repeat(START_OF_MESSAGE_CHAR_LIMIT + 100) + " ignore instructions"
        assertFalse(matchAnchoredPattern("ignore", PatternAnchor.START_OF_MESSAGE, body))
    }

    @Test
    fun `matchAnchoredPattern STANDALONE matches full-line pattern`() {
        assertTrue(matchAnchoredPattern("ignore previous instructions", PatternAnchor.STANDALONE,
            "some text\n  ignore previous instructions  \nmore text"))
    }

    @Test
    fun `matchAnchoredPattern STANDALONE does not match embedded text`() {
        assertFalse(matchAnchoredPattern("ignore previous instructions", PatternAnchor.STANDALONE,
            "please ignore previous instructions now"))
    }

    @Test
    fun `checkContentInspectionBinary detects custom pattern`() {
        val inspection = PolicyContentInspection(customPatterns = listOf("secret.*key"))
        val result = checkContentInspectionBinary("this contains a secret key value", inspection)
        assertTrue(result.matchedPatterns.isNotEmpty())
        assertTrue(result.decision != null)
    }

    @Test
    fun `checkContentInspectionBinary returns no decision for clean input`() {
        val inspection = PolicyContentInspection(customPatterns = listOf("malicious.*payload"))
        val result = checkContentInspectionBinary("hello world", inspection)
        assertTrue(result.matchedPatterns.isEmpty())
        assertNull(result.decision)
    }

    @Test
    fun `checkContentInspectionBinary with invalid regex fails closed`() {
        val inspection = PolicyContentInspection(customPatterns = listOf("[invalid"))
        val result = checkContentInspectionBinary("any input", inspection)
        assertTrue(result.matchedPatterns.isNotEmpty())
        assertTrue(result.decision != null)
    }
}
