package com.mustafadakhel.oag.pipeline.network

import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyUrlInspection
import com.mustafadakhel.oag.policy.core.ReasonCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class PathAnalysisTest {

    @Test
    fun `invalid percent-encoding denied by default`() {
        val defaults = PolicyDefaults(urlInspection = PolicyUrlInspection())
        val result = checkPathAnalysis("/api?token=abc&x=%ZZ", defaults)
        assertNotNull(result.decision)
        assertEquals(ReasonCode.INVALID_PERCENT_ENCODING_BLOCKED, result.decision?.reasonCode)
    }

    @Test
    fun `valid percent-encoding allowed`() {
        val defaults = PolicyDefaults(urlInspection = PolicyUrlInspection())
        val result = checkPathAnalysis("/api?token=abc%20def", defaults)
        assertNull(result.decision)
    }

    @Test
    fun `trailing percent sign denied`() {
        val defaults = PolicyDefaults(urlInspection = PolicyUrlInspection())
        val result = checkPathAnalysis("/api?x=hello%", defaults)
        assertNotNull(result.decision)
        assertEquals(ReasonCode.INVALID_PERCENT_ENCODING_BLOCKED, result.decision?.reasonCode)
    }

    @Test
    fun `percent followed by one hex digit denied`() {
        val defaults = PolicyDefaults(urlInspection = PolicyUrlInspection())
        val result = checkPathAnalysis("/api?x=%2", defaults)
        assertNotNull(result.decision)
    }

    @Test
    fun `invalid percent-encoding allowed when explicitly disabled`() {
        val defaults = PolicyDefaults(
            urlInspection = PolicyUrlInspection(blockInvalidPercentEncoding = false)
        )
        val result = checkPathAnalysis("/api?x=%ZZ", defaults)
        assertNull(result.decision)
    }

    @Test
    fun `path without query string passes percent check`() {
        val defaults = PolicyDefaults(urlInspection = PolicyUrlInspection())
        val result = checkPathAnalysis("/api/resource", defaults)
        assertNull(result.decision)
    }
}
