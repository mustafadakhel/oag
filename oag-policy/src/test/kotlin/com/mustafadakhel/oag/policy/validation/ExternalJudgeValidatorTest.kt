package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyExternalJudge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ExternalJudgeValidatorTest {

    private fun validate(config: PolicyExternalJudge) = config.validate("test")

    @Test
    fun `enabled without endpoint_url fails`() {
        val errors = validate(PolicyExternalJudge(enabled = true))
        assertTrue(errors.any { "endpoint_url" in it.path })
    }

    @Test
    fun `invalid URL scheme fails`() {
        val errors = validate(PolicyExternalJudge(endpointUrl = "ftp://example.com/judge"))
        assertTrue(errors.any { "http or https" in it.message })
    }

    @Test
    fun `valid https URL passes`() {
        val errors = validate(PolicyExternalJudge(endpointUrl = "https://judge.example.com/api"))
        assertTrue(errors.none { "endpoint_url" in it.path })
    }

    @Test
    fun `timeout 0 fails`() {
        val errors = validate(PolicyExternalJudge(timeoutMs = 0))
        assertTrue(errors.any { "timeout_ms" in it.path })
    }

    @Test
    fun `invalid trigger mode fails`() {
        val errors = validate(PolicyExternalJudge(triggerMode = "never"))
        assertTrue(errors.any { "trigger_mode" in it.path })
    }

    @Test
    fun `valid trigger modes pass`() {
        assertTrue(validate(PolicyExternalJudge(triggerMode = "always")).none { "trigger_mode" in it.path })
        assertTrue(validate(PolicyExternalJudge(triggerMode = "uncertain_only")).none { "trigger_mode" in it.path })
    }

    @Test
    fun `invalid on_error fails`() {
        val errors = validate(PolicyExternalJudge(onError = "retry"))
        assertTrue(errors.any { "on_error" in it.path })
    }

    @Test
    fun `valid on_error values pass`() {
        assertTrue(validate(PolicyExternalJudge(onError = "deny")).none { "on_error" in it.path })
        assertTrue(validate(PolicyExternalJudge(onError = "allow")).none { "on_error" in it.path })
        assertTrue(validate(PolicyExternalJudge(onError = "skip")).none { "on_error" in it.path })
    }

    @Test
    fun `deny_threshold out of range fails`() {
        assertTrue(validate(PolicyExternalJudge(denyThreshold = 0.0)).any { "deny_threshold" in it.path })
        assertTrue(validate(PolicyExternalJudge(denyThreshold = 1.1)).any { "deny_threshold" in it.path })
    }

    @Test
    fun `deny_threshold 0_5 passes`() {
        assertTrue(validate(PolicyExternalJudge(denyThreshold = 0.5)).none { "deny_threshold" in it.path })
    }

    @Test
    fun `max_response_bytes 0 fails`() {
        assertTrue(validate(PolicyExternalJudge(maxResponseBytes = 0)).any { "max_response_bytes" in it.path })
    }

    @Test
    fun `fully valid config produces no errors`() {
        val errors = validate(PolicyExternalJudge(
            enabled = true,
            endpointUrl = "https://judge.example.com/api",
            timeoutMs = 3000,
            triggerMode = "uncertain_only",
            onError = "skip",
            denyThreshold = 0.7,
            maxResponseBytes = 65536
        ))
        assertEquals(emptyList(), errors)
    }
}
