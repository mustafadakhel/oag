package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.policy.core.PolicyAnchoredPattern
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.pipeline.inspection.resolveContentInspection
import com.mustafadakhel.oag.pipeline.inspection.resolveCredentialDetection
import com.mustafadakhel.oag.pipeline.inspection.resolveDataClassification
import com.mustafadakhel.oag.pipeline.inspection.resolveResponseDataClassification
import com.mustafadakhel.oag.pipeline.inspection.resolveStreamingScanEnabled

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BodyInspectionTest {

    @Test
    fun `resolveContentInspection returns null when no rule or defaults`() {
        assertNull(resolveContentInspection(null, null))
    }

    @Test
    fun `resolveContentInspection returns null when rule skips inspection`() {
        val rule = PolicyRule(host = "example.com", skipContentInspection = true,
            contentInspection = PolicyContentInspection(enableBuiltinPatterns = true))
        assertNull(resolveContentInspection(rule, null))
    }

    @Test
    fun `resolveContentInspection returns rule-level when builtin patterns enabled`() {
        val inspection = PolicyContentInspection(enableBuiltinPatterns = true)
        val rule = PolicyRule(host = "example.com", contentInspection = inspection)
        assertEquals(inspection, resolveContentInspection(rule, null))
    }

    @Test
    fun `resolveContentInspection returns rule-level with custom patterns`() {
        val inspection = PolicyContentInspection(customPatterns = listOf("pattern.*"))
        val rule = PolicyRule(host = "example.com", contentInspection = inspection)
        assertNotNull(resolveContentInspection(rule, null))
    }

    @Test
    fun `resolveContentInspection returns rule-level with anchored patterns`() {
        val inspection = PolicyContentInspection(anchoredPatterns = listOf(
            PolicyAnchoredPattern(pattern = "test")))
        val rule = PolicyRule(host = "example.com", contentInspection = inspection)
        assertNotNull(resolveContentInspection(rule, null))
    }

    @Test
    fun `resolveContentInspection returns null for empty rule-level inspection`() {
        val inspection = PolicyContentInspection()
        val rule = PolicyRule(host = "example.com", contentInspection = inspection)
        assertNull(resolveContentInspection(rule, null))
    }

    @Test
    fun `resolveContentInspection falls back to defaults`() {
        val inspection = PolicyContentInspection(enableBuiltinPatterns = true)
        val defaults = PolicyDefaults(contentInspection = inspection)
        val rule = PolicyRule(host = "example.com")
        assertEquals(inspection, resolveContentInspection(rule, defaults))
    }

    @Test
    fun `resolveCredentialDetection returns false when rule skips`() {
        val rule = PolicyRule(host = "example.com", skipOutboundCredentialDetection = true)
        val defaults = PolicyDefaults(outboundCredentialDetection = true)
        assertFalse(resolveCredentialDetection(rule, defaults))
    }

    @Test
    fun `resolveCredentialDetection returns true from defaults`() {
        val rule = PolicyRule(host = "example.com")
        val defaults = PolicyDefaults(outboundCredentialDetection = true)
        assertTrue(resolveCredentialDetection(rule, defaults))
    }

    @Test
    fun `resolveCredentialDetection returns false when defaults disabled`() {
        val rule = PolicyRule(host = "example.com")
        val defaults = PolicyDefaults(outboundCredentialDetection = false)
        assertFalse(resolveCredentialDetection(rule, defaults))
    }

    @Test
    fun `resolveDataClassification returns null when rule skips`() {
        val rule = PolicyRule(host = "example.com", skipDataClassification = true,
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true))
        assertNull(resolveDataClassification(rule, null))
    }

    @Test
    fun `resolveDataClassification returns rule-level config`() {
        val dc = PolicyDataClassification(enableBuiltinPatterns = true)
        val rule = PolicyRule(host = "example.com", dataClassification = dc)
        assertEquals(dc, resolveDataClassification(rule, null))
    }

    @Test
    fun `resolveDataClassification falls back to defaults`() {
        val dc = PolicyDataClassification(enableBuiltinPatterns = true)
        val defaults = PolicyDefaults(dataClassification = dc)
        assertEquals(dc, resolveDataClassification(PolicyRule(host = "example.com"), defaults))
    }

    @Test
    fun `resolveStreamingScanEnabled returns true by default`() {
        assertTrue(resolveStreamingScanEnabled(null, null))
    }

    @Test
    fun `resolveStreamingScanEnabled uses rule-level setting`() {
        val inspection = PolicyContentInspection(scanStreamingResponses = false)
        val rule = PolicyRule(host = "example.com", contentInspection = inspection)
        assertFalse(resolveStreamingScanEnabled(rule, null))
    }

    @Test
    fun `resolveStreamingScanEnabled falls back to defaults contentInspection`() {
        val defaults = PolicyDefaults(contentInspection = PolicyContentInspection(scanStreamingResponses = false))
        assertTrue(resolveStreamingScanEnabled(null, null))
        assertFalse(resolveStreamingScanEnabled(null, defaults))
    }

    @Test
    fun `resolveStreamingScanEnabled falls back to defaults top-level`() {
        val defaults = PolicyDefaults(scanStreamingResponses = false)
        assertFalse(resolveStreamingScanEnabled(null, defaults))
    }

    // --- resolveResponseDataClassification ---

    @Test
    fun `resolveResponseDataClassification returns null when no config`() {
        assertNull(resolveResponseDataClassification(null, null))
    }

    @Test
    fun `resolveResponseDataClassification returns null when scanResponses not set`() {
        val defaults = PolicyDefaults(
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true)
        )
        assertNull(resolveResponseDataClassification(null, defaults))
    }

    @Test
    fun `resolveResponseDataClassification returns null when scanResponses false`() {
        val defaults = PolicyDefaults(
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true, scanResponses = false)
        )
        assertNull(resolveResponseDataClassification(null, defaults))
    }

    @Test
    fun `resolveResponseDataClassification returns config when scanResponses true`() {
        val defaults = PolicyDefaults(
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true, scanResponses = true)
        )
        val result = resolveResponseDataClassification(null, defaults)
        assertNotNull(result)
        assertEquals(true, result.enableBuiltinPatterns)
    }

    @Test
    fun `resolveResponseDataClassification returns null when skip on rule`() {
        val rule = PolicyRule(
            host = "example.com",
            skipDataClassification = true,
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true, scanResponses = true)
        )
        assertNull(resolveResponseDataClassification(rule, null))
    }

    @Test
    fun `resolveResponseDataClassification uses rule config over defaults`() {
        val rule = PolicyRule(
            host = "example.com",
            dataClassification = PolicyDataClassification(
                enableBuiltinPatterns = true,
                scanResponses = true,
                categories = listOf("pii")
            )
        )
        val defaults = PolicyDefaults(
            dataClassification = PolicyDataClassification(enableBuiltinPatterns = true, scanResponses = true)
        )
        val result = resolveResponseDataClassification(rule, defaults)
        assertNotNull(result)
        assertEquals(listOf("pii"), result.categories)
    }

    @Test
    fun `resolveResponseDataClassification returns null when no patterns enabled`() {
        val defaults = PolicyDefaults(
            dataClassification = PolicyDataClassification(scanResponses = true)
        )
        assertNull(resolveResponseDataClassification(null, defaults))
    }
}
